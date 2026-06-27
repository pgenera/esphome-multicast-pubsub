package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Bridge wires an MQTT client and a mpubsub socket together
// per the configured entries. Each entry is one-directional.
type Bridge struct {
	cfg   *Config
	scope Scope
	mqtt  mqtt.Client
	mcast *MulticastSocket

	// replay rejects stale / duplicate encrypted packets when
	// encryption.replay_window is configured (inert otherwise).
	replay *replayGuard

	// crcToMQTT[topic_crc] = list of MQTT topic + QoS/retain to publish to
	// when a multicast packet arrives with that CRC. Multiple entries are
	// possible if the user configures more than one mqtt destination for
	// the same mpubsub topic.
	crcToMQTT map[uint32][]mpubsubToMQTTRoute

	// indefiniteJobs holds a cancel channel per mpubsub topic that has an
	// active indefinite-retransmit goroutine. Closing the channel signals
	// the goroutine to exit; a new indefinite publish for the same topic
	// closes the prior channel and installs a new one.
	indefiniteMu   sync.Mutex
	indefiniteJobs map[string]chan struct{}

	log *slog.Logger

	// Verbose, when true, prints one line per forwarded message to stdout
	// in the form  "<source> -> <destination> : <payload>".
	Verbose bool
}

// verbosef prints one trace line to stdout (not stderr/slog) when verbose
// mode is on. Payloads are rendered with %q so binary bytes are safe.
func (b *Bridge) verbosef(src, dst string, payload []byte) {
	if !b.Verbose {
		return
	}
	fmt.Fprintf(os.Stdout, "%s -> %s : %q\n", src, dst, payload)
}

type mpubsubToMQTTRoute struct {
	MQTTTopic         string
	RequireEncryption bool
	// Schema, when non-nil, restricts this route to PROTO packets whose
	// SCHEMA_ID matches; the body is decoded and re-emitted as JSON.
	// When nil, the route forwards RAW packets verbatim.
	Schema *Schema
}

func NewBridge(cfg *Config, log *slog.Logger) (*Bridge, error) {
	scope, err := ParseScope(cfg.MPubsub.Scope)
	if err != nil {
		return nil, err
	}
	sock, err := OpenMulticastSocket(cfg.MPubsub)
	if err != nil {
		return nil, err
	}

	opts := mqtt.NewClientOptions().
		AddBroker(cfg.MQTT.Broker).
		SetClientID(cfg.MQTT.ClientID).
		SetAutoReconnect(true).
		SetCleanSession(true)
	if cfg.MQTT.Username != "" {
		opts.SetUsername(cfg.MQTT.Username)
		opts.SetPassword(cfg.MQTT.Password)
	}
	client := mqtt.NewClient(opts)

	b := &Bridge{
		cfg:            cfg,
		scope:          scope,
		mqtt:           client,
		mcast:          sock,
		crcToMQTT:      make(map[uint32][]mpubsubToMQTTRoute),
		indefiniteJobs: make(map[string]chan struct{}),
		// The bridge runs on a real host, so a generous de-dup cache costs
		// little; 4096 entries spans a busy window without evicting early.
		replay: newReplayGuard(cfg.MPubsub.ReplayWindowSeconds, 4096),
		log:    log,
	}
	return b, nil
}

// randNonce returns a fresh 12-byte ChaCha20-Poly1305 nonce. It must be
// unique per key; a 96-bit random value collides only after ~2^48 messages,
// far beyond any bridge's lifetime. Its low 32 bits double as the replay
// de-dup identity on the receive side.
func randNonce() []byte {
	b := make([]byte, aeadNonceLen)
	// crypto/rand.Read never returns a short read without an error; on the
	// vanishingly unlikely error we fall back to a zero nonce, which only
	// weakens de-dup (and nonce uniqueness) for that one packet.
	_, _ = rand.Read(b)
	return b
}

func (b *Bridge) Run(ctx context.Context) error {
	if token := b.mqtt.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}
	b.log.Info("mqtt connected", "broker", b.cfg.MQTT.Broker)

	// Configure the routing tables and joins from the config.
	for _, entry := range b.cfg.Bridges {
		switch entry.Direction {
		case DirMQTTToMPubsub:
			// Capture the loop variable so the closure refers to this entry.
			e := entry
			h := func(_ mqtt.Client, msg mqtt.Message) {
				// If the user didn't pin an mpubsub_topic, use the
				// resolved MQTT topic. This is the case that makes
				// wildcard subscriptions (`home/+/temp`) useful: each
				// match keeps its own mpubsub identity instead of being
				// collapsed onto one multicast group.
				mpubsubTopic := e.MPubsubTopic
				if mpubsubTopic == "" {
					mpubsubTopic = msg.Topic()
				}
				group := TopicToGroup(mpubsubTopic, b.scope)
				b.handleMQTTMessage(mpubsubTopic, group, msg, e.schemaPtr)
			}
			// MQTT delivers messages at min(publish_qos, subscribe_qos). To
			// surface the publisher's QoS to promote_qos, we must subscribe
			// at QoS 2 so the broker passes the original QoS through. When
			// promote_qos is off, honor the user's configured subscribe QoS.
			subQoS := b.cfg.MQTT.QoS
			if b.cfg.MPubsub.PromoteQoS {
				subQoS = 2
			}
			if token := b.mqtt.Subscribe(e.MQTTTopic, subQoS, h); token.Wait() && token.Error() != nil {
				return token.Error()
			}
			mpubsubTopicLog := e.MPubsubTopic
			if mpubsubTopicLog == "" {
				mpubsubTopicLog = "(use mqtt topic)"
			}
			b.log.Info("subscribed mqtt -> mpubsub",
				"mqtt_topic", e.MQTTTopic, "mpubsub_topic", mpubsubTopicLog,
				"sub_qos", subQoS)
		case DirMPubsubToMQTT:
			group := TopicToGroup(entry.MPubsubTopic, b.scope)
			if err := b.mcast.Join(group); err != nil {
				return err
			}
			crc := TopicCRC32(entry.MPubsubTopic)
			b.crcToMQTT[crc] = append(b.crcToMQTT[crc], mpubsubToMQTTRoute{
				MQTTTopic:         entry.MQTTTopic,
				RequireEncryption: entry.RequireEncryption,
				Schema:            entry.schemaPtr,
			})
			schemaLog := "(raw)"
			if entry.schemaPtr != nil {
				schemaLog = fmt.Sprintf("%s/0x%04x", entry.schemaPtr.ID, entry.schemaPtr.SchemaID())
			}
			b.log.Info("joined mpubsub -> mqtt",
				"mpubsub_topic", entry.MPubsubTopic, "mqtt_topic", entry.MQTTTopic,
				"group", group.String(), "crc", crc,
				"require_encryption", entry.RequireEncryption,
				"schema", schemaLog)
		}
	}

	// Multicast receiver pump.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.mcastReceiveLoop(ctx)
	}()

	<-ctx.Done()
	b.log.Info("shutting down")
	// Tell any indefinite-retransmit goroutines to exit before we tear
	// down the multicast socket they're writing to.
	b.indefiniteMu.Lock()
	for topic, ch := range b.indefiniteJobs {
		close(ch)
		delete(b.indefiniteJobs, topic)
	}
	b.indefiniteMu.Unlock()
	b.mcast.Close()
	b.mqtt.Disconnect(250)
	wg.Wait()
	return nil
}

func (b *Bridge) handleMQTTMessage(mpubsubTopic string, group net.IP, msg mqtt.Message, schema *Schema) {
	body := msg.Payload()
	encoding := byte(encodingRaw)
	if schema != nil {
		protoBody, err := JSONToProto(schema, msg.Payload())
		if err != nil {
			b.log.Warn("json -> proto encode failed",
				"mqtt_topic", msg.Topic(), "mpubsub_topic", mpubsubTopic,
				"schema", schema.ID, "err", err)
			return
		}
		// mpubsub PROTO body = 2-byte LE SCHEMA_ID || protobuf bytes.
		sid := schema.SchemaID()
		body = make([]byte, 2+len(protoBody))
		body[0] = byte(sid)
		body[1] = byte(sid >> 8)
		copy(body[2:], protoBody)
		encoding = encodingProto
	}
	// Stamp encrypted publishes with the current time + a random nonce so a
	// replay-checking receiver can reject stale/duplicate copies. Ignored for
	// plaintext (key == nil).
	var ts uint32
	var nonce []byte
	if b.cfg.MPubsub.EncryptionKey != nil {
		ts = uint32(time.Now().Unix())
		nonce = randNonce()
	}
	pkt, err := EncodePacket(mpubsubTopic, body, encoding, b.cfg.MPubsub.EncryptionKey, ts, nonce)
	if err != nil {
		b.log.Warn("encode packet failed",
			"mqtt_topic", msg.Topic(), "mpubsub_topic", mpubsubTopic, "err", err)
		return
	}
	// Compute the effective retransmit_count for this message. The QoS
	// promotion (if enabled) only ever raises the count; it never
	// downgrades a config-level indefinite to finite.
	count := b.effectiveRetransmitCount(msg.Qos())
	// Any new publish to a topic supersedes a prior indefinite chain for
	// that topic, even if the new publish is finite. Mirrors the C++ side.
	b.cancelIndefinite(mpubsubTopic)
	if err := b.mcast.SendTo(group, pkt); err != nil {
		b.log.Warn("multicast send failed",
			"mpubsub_topic", mpubsubTopic, "group", group.String(), "err", err)
		return
	}
	b.log.Debug("mqtt -> mpubsub",
		"mqtt_topic", msg.Topic(), "mpubsub_topic", mpubsubTopic,
		"bytes", len(msg.Payload()), "qos", msg.Qos(), "retransmit_count", count)
	b.verbosef(msg.Topic(), group.String(), msg.Payload())
	if count == -1 {
		b.startIndefinite(mpubsubTopic, group, pkt)
	} else if count > 1 {
		b.scheduleFiniteRetransmits(mpubsubTopic, group, pkt, count)
	}
}

// effectiveRetransmitCount adapts the configured retransmit_count to the
// incoming MQTT QoS when promote_qos is set. The mapping is "QoS bumps
// the count up, never down" so an already-indefinite config stays
// indefinite for QoS 0.
func (b *Bridge) effectiveRetransmitCount(qos byte) int {
	base := b.cfg.MPubsub.RetransmitCount
	if !b.cfg.MPubsub.PromoteQoS {
		return base
	}
	switch qos {
	case 0:
		return base
	case 1:
		if base == -1 {
			return -1
		}
		if base < 3 {
			return 3
		}
		return base
	default: // 2 and any future MQTT5 values >= 2
		return -1
	}
}

// scheduleFiniteRetransmits fires off (count - 1) additional sends of the
// same pre-encoded datagram, spaced by the configured delay. Runs on its
// own goroutine so the MQTT callback returns immediately; the first send
// has already happened synchronously. delay = 0 is fine (time.Sleep(0)
// returns immediately) but each iteration still yields, so the loop
// won't starve other goroutines.
func (b *Bridge) scheduleFiniteRetransmits(mpubsubTopic string, group net.IP, pkt []byte, count int) {
	delay := b.cfg.MPubsub.RetransmitDelay
	go func() {
		for i := 1; i < count; i++ {
			if delay > 0 {
				time.Sleep(delay)
			}
			if err := b.mcast.SendTo(group, pkt); err != nil {
				b.log.Warn("multicast retransmit failed",
					"mpubsub_topic", mpubsubTopic, "group", group.String(),
					"attempt", i+1, "err", err)
				return
			}
		}
	}()
}

// startIndefinite installs a per-topic goroutine that resends pkt at
// the configured delay until its cancel channel is closed. Any prior
// indefinite job for the same topic has already been cancelled by the
// caller via cancelIndefinite().
func (b *Bridge) startIndefinite(mpubsubTopic string, group net.IP, pkt []byte) {
	delay := b.cfg.MPubsub.RetransmitDelay
	cancel := make(chan struct{})
	b.indefiniteMu.Lock()
	b.indefiniteJobs[mpubsubTopic] = cancel
	b.indefiniteMu.Unlock()
	go func() {
		ticker := time.NewTicker(delay)
		defer ticker.Stop()
		for {
			select {
			case <-cancel:
				return
			case <-ticker.C:
				if err := b.mcast.SendTo(group, pkt); err != nil {
					b.log.Warn("multicast indefinite resend failed",
						"mpubsub_topic", mpubsubTopic, "group", group.String(), "err", err)
					// Keep looping -- a transient ENETUNREACH (interface
					// briefly down) shouldn't end the chain.
				}
			}
		}
	}()
}

// cancelIndefinite stops the current indefinite-retransmit goroutine for
// the topic, if any. Safe to call when no job is active.
func (b *Bridge) cancelIndefinite(mpubsubTopic string) {
	b.indefiniteMu.Lock()
	defer b.indefiniteMu.Unlock()
	if ch, ok := b.indefiniteJobs[mpubsubTopic]; ok {
		close(ch)
		delete(b.indefiniteJobs, mpubsubTopic)
	}
}

func (b *Bridge) mcastReceiveLoop(ctx context.Context) {
	buf := make([]byte, maxDatagram)
	for {
		if ctx.Err() != nil {
			return
		}
		n, src, err := b.mcast.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			b.log.Warn("mcast read error", "err", err)
			continue
		}
		pkt, err := DecodePacket(buf[:n], b.cfg.MPubsub.EncryptionKey)
		if err != nil {
			b.log.Debug("dropped packet", "err", err, "bytes", n)
			continue
		}
		// Replay rejection for encrypted packets: drop anything stale or
		// repeating a recently-seen nonce. The bridge always has a real
		// clock, so now_valid is true.
		if pkt.WasEncrypted && b.replay.enabled() {
			if !b.replay.accept(uint32(time.Now().Unix()), true, pkt.Timestamp, pkt.Nonce) {
				b.log.Debug("dropped replayed/stale packet",
					"crc", pkt.TopicCRC, "ts", pkt.Timestamp, "nonce", pkt.Nonce)
				continue
			}
		}
		routes := b.crcToMQTT[pkt.TopicCRC]
		if len(routes) == 0 {
			continue
		}
		// Pre-decode the PROTO body once if needed: every schemaful route
		// for this CRC peels the same 2-byte SCHEMA_ID prefix off the
		// same body. Different routes may target different schemas, so
		// the actual decode happens per-route below.
		var protoSchemaID uint16
		var protoBody []byte
		if pkt.Encoding == encodingProto {
			if len(pkt.Payload) < 2 {
				b.log.Debug("proto packet too short for SCHEMA_ID", "crc", pkt.TopicCRC)
				continue
			}
			protoSchemaID = uint16(pkt.Payload[0]) | uint16(pkt.Payload[1])<<8
			protoBody = pkt.Payload[2:]
		}
		for _, r := range routes {
			if r.RequireEncryption && !pkt.WasEncrypted {
				b.log.Debug("drop plaintext packet for require_encryption route",
					"mpubsub_crc", pkt.TopicCRC, "mqtt_topic", r.MQTTTopic)
				continue
			}
			var mqttPayload []byte
			switch {
			case r.Schema == nil && pkt.Encoding == encodingRaw:
				mqttPayload = pkt.Payload
			case r.Schema == nil && pkt.Encoding == encodingProto:
				// Raw route + proto packet: an MQTT subscriber has no
				// way to interpret the 2-byte SCHEMA_ID prefix. Drop.
				b.log.Debug("skip proto packet on raw route",
					"crc", pkt.TopicCRC, "mqtt_topic", r.MQTTTopic)
				continue
			case r.Schema != nil && pkt.Encoding != encodingProto:
				b.log.Debug("skip non-proto packet on schema route",
					"crc", pkt.TopicCRC, "mqtt_topic", r.MQTTTopic, "encoding", pkt.Encoding)
				continue
			case r.Schema != nil && pkt.Encoding == encodingProto:
				if protoSchemaID != r.Schema.SchemaID() {
					b.log.Debug("schema id mismatch on proto route",
						"crc", pkt.TopicCRC, "mqtt_topic", r.MQTTTopic,
						"want_sid", r.Schema.SchemaID(), "got_sid", protoSchemaID)
					continue
				}
				jsonBytes, err := ProtoToJSON(r.Schema, protoBody)
				if err != nil {
					b.log.Warn("proto -> json decode failed",
						"mqtt_topic", r.MQTTTopic, "schema", r.Schema.ID, "err", err)
					continue
				}
				mqttPayload = jsonBytes
			}
			t := b.mqtt.Publish(r.MQTTTopic, b.cfg.MQTT.QoS, b.cfg.MQTT.Retain, mqttPayload)
			// Don't block the multicast loop on broker round-trips. Log
			// failures asynchronously.
			go func(tok mqtt.Token, mqttTopic string) {
				if tok.Wait() && tok.Error() != nil {
					b.log.Warn("mqtt publish failed", "mqtt_topic", mqttTopic, "err", tok.Error())
				}
			}(t, r.MQTTTopic)
			b.log.Debug("mpubsub -> mqtt", "mqtt_topic", r.MQTTTopic, "bytes", len(mqttPayload))
			srcLabel := "mpubsub"
			if src != nil {
				srcLabel = src.IP.String()
			}
			b.verbosef(srcLabel, r.MQTTTopic, mqttPayload)
		}
	}
}
