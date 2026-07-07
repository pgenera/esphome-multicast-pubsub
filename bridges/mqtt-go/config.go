package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Direction tags a bridge entry. Each entry is uni-directional; declare two
// entries to mirror a topic both ways. Keeping it asymmetric makes loop risk
// explicit -- using the same topic name on both sides with a broker that
// re-delivers to its publisher would feed back on itself.
type Direction string

const (
	DirMQTTToMPubsub Direction = "mqtt_to_mpubsub"
	DirMPubsubToMQTT Direction = "mpubsub_to_mqtt"
)

type MQTTConfig struct {
	Broker   string `yaml:"broker"`    // e.g. tcp://broker:1883, ssl://broker:8883
	ClientID string `yaml:"client_id"` // default "mpubsub-bridge"
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	QoS      byte   `yaml:"qos"` // default 0
	Retain   bool   `yaml:"retain"`
}

type MPubsubConfig struct {
	Port      uint16 `yaml:"port"`      // default 18512
	Scope     string `yaml:"scope"`     // default link-local
	Hops      int    `yaml:"hops"`      // default 1
	Interface string `yaml:"interface"` // default: kernel-picked

	// RetransmitCount is the number of UDP datagrams emitted per logical
	// publish.
	//   1   : no retransmission (default)
	//   N>1 : send N packets total, (N-1) deferred on a goroutine
	//   -1  : indefinite -- keep emitting at RetransmitDelay until
	//         another publish for the same topic supersedes it. Requires
	//         RetransmitDelay >= 1s (enforced at config time).
	// The first send is always synchronous.
	RetransmitCount int `yaml:"retransmit_count"`
	// RetransmitDelay is the spacing between successive sends. Accepts
	// any Go duration string (e.g. "100ms", "1s", "0s"). 0 is supported
	// for finite counts; -1 (indefinite) requires >= 1s.
	RetransmitDelayRaw string        `yaml:"retransmit_delay"`
	RetransmitDelay    time.Duration `yaml:"-"`

	// PromoteQoS adapts the effective retransmit_count based on the
	// incoming MQTT message's QoS, on the theory that a QoS>0 publisher
	// "cared more" about delivery and the UDP-multicast hop should
	// reflect that:
	//   QoS 0  → RetransmitCount  (unchanged)
	//   QoS 1  → max(RetransmitCount, 3)
	//   QoS 2  → -1 (indefinite, capped by the topic-supersede rule)
	// Default false to keep behavior predictable.
	PromoteQoS bool `yaml:"promote_qos"`

	// Encryption mirrors the C++ `mpubsub: encryption: key:` block: a
	// passphrase that is SHA-256d to a 32-byte ChaCha20-Poly1305 key. When set, the
	// bridge encrypts every mqtt → mpubsub publish and can decrypt encrypted
	// mpubsub → mqtt packets. Leave empty for plaintext.
	Encryption EncryptionConfig `yaml:"encryption"`

	// EncryptionKey is the 32-byte SHA-256 of Encryption.Key, derived at
	// config-load time. Not user-facing; populated by applyDefaults.
	EncryptionKey []byte `yaml:"-"`

	// ReplayWindowSeconds is the parsed encryption.replay_window in seconds
	// (0 = replay protection off). Populated by applyDefaults.
	ReplayWindowSeconds uint32 `yaml:"-"`
}

// EncryptionConfig matches the ESPHome packet_transport / mpubsub idiom
// of `encryption: { key: "..." }` so YAML blocks are familiar.
type EncryptionConfig struct {
	Key string `yaml:"key"`
	// ReplayWindow enables replay protection: encrypted packets stamped more
	// than this far from the bridge clock, or repeating a recently-seen
	// nonce, are dropped. Any Go duration string (e.g. "30s"). Empty = off.
	ReplayWindow string `yaml:"replay_window"`
}

type BridgeEntry struct {
	Direction    Direction `yaml:"direction"`
	MQTTTopic    string    `yaml:"mqtt_topic"`
	MPubsubTopic string    `yaml:"mpubsub_topic"`
	// RequireEncryption applies only to mpubsub_to_mqtt entries: plaintext
	// multicast datagrams for this mpubsub topic are dropped at the
	// receiver instead of being forwarded to MQTT. Mirrors the C++ side's
	// per-topic require_encryption on on_message / sensor.subscribe.
	// Setting it requires mpubsub.encryption.key to be configured.
	RequireEncryption bool `yaml:"require_encryption"`
	// Schema references a top-level schemas entry by id. When set:
	//   mqtt_to_mpubsub: the MQTT payload is parsed as JSON and re-encoded
	//   as a protobuf body with that schema's SCHEMA_ID prefix; the wire
	//   ENCODING byte is PROTO.
	//   mpubsub_to_mqtt: only PROTO packets matching SCHEMA_ID are
	//   forwarded; their bodies are decoded and re-emitted as JSON on MQTT.
	// When unset, the entry is RAW pass-through (the original behavior).
	Schema string `yaml:"schema"`

	// resolved at load time; not user-facing.
	schemaPtr *Schema
}

// SchemaConfig is one entry in the top-level `schemas:` list.
type SchemaConfig struct {
	ID     string              `yaml:"id"`
	Fields []SchemaFieldConfig `yaml:"fields"`
}

type SchemaFieldConfig struct {
	Tag      uint32 `yaml:"tag"`
	Type     string `yaml:"type"`
	Name     string `yaml:"name"`
	Repeated bool   `yaml:"repeated"`
}

type Config struct {
	MQTT    MQTTConfig     `yaml:"mqtt"`
	MPubsub MPubsubConfig  `yaml:"mpubsub"`
	Schemas []SchemaConfig `yaml:"schemas"`
	Bridges []BridgeEntry  `yaml:"bridges"`

	// JSONTranslation gates the dynamic JSON <-> proto translation feature.
	// Default false: a config with `schemas:` or per-entry `schema:` is
	// rejected. This keeps the feature opt-in so a bridge binary upgrade
	// can't silently start reinterpreting payloads on a deployment that
	// didn't ask for it.
	JSONTranslation bool `yaml:"json_translation"`

	// schemasByID is the validated lookup, built at load time.
	schemasByID map[string]*Schema
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if err := c.applyDefaults(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() error {
	if c.MQTT.ClientID == "" {
		c.MQTT.ClientID = "mpubsub-bridge"
	}
	if c.MPubsub.Port == 0 {
		c.MPubsub.Port = 18512
	}
	if c.MPubsub.Scope == "" {
		c.MPubsub.Scope = "link-local"
	}
	if c.MPubsub.Hops == 0 {
		c.MPubsub.Hops = 1
	}
	// Zero value (Go's int default) means "not set in YAML"; map to the
	// real default of 1. validate() accepts 1..255 and -1.
	if c.MPubsub.RetransmitCount == 0 {
		c.MPubsub.RetransmitCount = 1
	}
	if c.MPubsub.RetransmitDelayRaw == "" {
		c.MPubsub.RetransmitDelay = 100 * time.Millisecond
	} else {
		d, err := time.ParseDuration(c.MPubsub.RetransmitDelayRaw)
		if err != nil {
			return fmt.Errorf("mpubsub.retransmit_delay %q: %w",
				c.MPubsub.RetransmitDelayRaw, err)
		}
		if d < 0 {
			return fmt.Errorf("mpubsub.retransmit_delay must be >= 0 (got %s)", d)
		}
		c.MPubsub.RetransmitDelay = d
	}
	if c.MPubsub.Encryption.Key != "" {
		c.MPubsub.EncryptionKey = DeriveKey(c.MPubsub.Encryption.Key)
	}
	if c.MPubsub.Encryption.ReplayWindow != "" {
		d, err := time.ParseDuration(c.MPubsub.Encryption.ReplayWindow)
		if err != nil {
			return fmt.Errorf("mpubsub.encryption.replay_window %q: %w",
				c.MPubsub.Encryption.ReplayWindow, err)
		}
		if d < 0 {
			return fmt.Errorf("mpubsub.encryption.replay_window must be >= 0 (got %s)", d)
		}
		// 0s explicitly disables replay protection (matches the ESPHome
		// component), so it needs neither a key nor a clock reference.
		if d > 0 {
			if len(c.MPubsub.EncryptionKey) == 0 {
				return fmt.Errorf("mpubsub.encryption.replay_window requires encryption.key")
			}
			c.MPubsub.ReplayWindowSeconds = uint32(d.Seconds())
		}
	}
	if !c.JSONTranslation {
		if len(c.Schemas) > 0 {
			return fmt.Errorf("schemas: configured but json_translation is false (default); set json_translation: true to enable JSON <-> proto translation")
		}
		for i, b := range c.Bridges {
			if b.Schema != "" {
				return fmt.Errorf("bridges[%d]: schema %q set but json_translation is false (default); set json_translation: true to enable", i, b.Schema)
			}
		}
		return nil
	}
	c.schemasByID = make(map[string]*Schema, len(c.Schemas))
	for i, sc := range c.Schemas {
		fields := make([]SchemaField, len(sc.Fields))
		for j, f := range sc.Fields {
			fields[j] = SchemaField{
				Name: f.Name, Type: f.Type, Tag: f.Tag, Repeated: f.Repeated,
			}
		}
		s, err := NewSchema(sc.ID, fields)
		if err != nil {
			return fmt.Errorf("schemas[%d]: %w", i, err)
		}
		if _, dup := c.schemasByID[sc.ID]; dup {
			return fmt.Errorf("schemas[%d]: duplicate id %q", i, sc.ID)
		}
		c.schemasByID[sc.ID] = s
	}
	for i := range c.Bridges {
		b := &c.Bridges[i]
		if b.Schema == "" {
			continue
		}
		s, ok := c.schemasByID[b.Schema]
		if !ok {
			return fmt.Errorf("bridges[%d]: schema %q not defined", i, b.Schema)
		}
		b.schemaPtr = s
	}
	return nil
}

func (c *Config) validate() error {
	if c.MQTT.Broker == "" {
		return fmt.Errorf("mqtt.broker is required")
	}
	if _, err := ParseScope(c.MPubsub.Scope); err != nil {
		return fmt.Errorf("mpubsub.%w", err)
	}
	if c.MPubsub.Hops < 1 || c.MPubsub.Hops > 255 {
		return fmt.Errorf("mpubsub.hops must be 1..255, got %d", c.MPubsub.Hops)
	}
	if c.MPubsub.RetransmitCount != -1 &&
		(c.MPubsub.RetransmitCount < 1 || c.MPubsub.RetransmitCount > 255) {
		return fmt.Errorf("mpubsub.retransmit_count must be 1..255 or -1 (indefinite); got %d",
			c.MPubsub.RetransmitCount)
	}
	if c.MPubsub.RetransmitCount == -1 && c.MPubsub.RetransmitDelay < time.Second {
		return fmt.Errorf(
			"mpubsub.retransmit_count: -1 (indefinite) requires retransmit_delay >= 1s; got %s",
			c.MPubsub.RetransmitDelay)
	}
	if len(c.Bridges) == 0 {
		return fmt.Errorf("at least one bridge entry is required")
	}
	for i, b := range c.Bridges {
		if b.MQTTTopic == "" {
			return fmt.Errorf("bridges[%d]: mqtt_topic is required", i)
		}
		switch b.Direction {
		case DirMQTTToMPubsub:
			// mpubsub_topic optional here: omit it to use the resolved
			// MQTT topic (msg.Topic()) as the mpubsub topic at delivery
			// time. This is what makes MQTT wildcard subscriptions like
			// `home/+/temp` useful -- each match keeps its identity
			// instead of being collapsed onto one multicast group.
		case DirMPubsubToMQTT:
			// mpubsub_topic is the join key; required and no wildcards
			// (the protocol has no concept of wildcard subscriptions).
			if b.MPubsubTopic == "" {
				return fmt.Errorf("bridges[%d]: mpubsub_topic is required for mpubsub_to_mqtt entries", i)
			}
			if strings.ContainsAny(b.MPubsubTopic, "+#") {
				return fmt.Errorf("bridges[%d]: mpubsub_topic %q contains MQTT wildcards; the mpubsub protocol has no wildcard subscriptions",
					i, b.MPubsubTopic)
			}
		default:
			return fmt.Errorf("bridges[%d]: unknown direction %q (want %q or %q)",
				i, b.Direction, DirMQTTToMPubsub, DirMPubsubToMQTT)
		}
		if b.RequireEncryption {
			if b.Direction != DirMPubsubToMQTT {
				return fmt.Errorf("bridges[%d]: require_encryption is only valid for mpubsub_to_mqtt entries (this one is %s)",
					i, b.Direction)
			}
			if len(c.MPubsub.EncryptionKey) == 0 {
				return fmt.Errorf("bridges[%d]: require_encryption needs mpubsub.encryption.key to be set", i)
			}
		}
	}
	return nil
}
