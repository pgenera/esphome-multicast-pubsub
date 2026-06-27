# mqtt-pubsub-bridge

A standalone Go daemon that mirrors messages between an MQTT broker and the
`mpubsub` IPv6 multicast fabric. Useful when:

- you have an existing MQTT-based deployment and want to expose those topics
  to multicast-only ESPHome devices, or
- you want a Linux host (Home Assistant, a logger, an analytics box) to
  ingest multicast publications without having to speak the wire format
  itself.

## Build

```
cd bridges/mqtt-go
go build -o mqtt-pubsub-bridge .
```

## Run

```
./mqtt-pubsub-bridge -config bridge.yaml
./mqtt-pubsub-bridge -config bridge.yaml -log-level debug
```

See [`bridge.example.yaml`](bridge.example.yaml) for the config shape.

## Config

| Section | Key | Default | Meaning |
|---------|-----|---------|---------|
| `mqtt` | `broker` | — | Required. `tcp://host:1883`, `ssl://host:8883`, `ws://...`, etc. |
| `mqtt` | `client_id` | `mpubsub-bridge` | Stable id helps reconnect logic on the broker. |
| `mqtt` | `username` / `password` | — | Optional credentials. |
| `mqtt` | `qos` | `0` | QoS for both subscribed and published MQTT topics. |
| `mqtt` | `retain` | `false` | Retain flag for messages bridged into MQTT. |
| `mpubsub` | `port` | `18512` | Must match the ESPHome devices. |
| `mpubsub` | `scope` | `link-local` | `link-local` / `site-local` / `organization-local`. |
| `mpubsub` | `hops` | `1` | Outgoing `IPV6_MULTICAST_HOPS`. |
| `mpubsub` | `retransmit_count` | `1` | Number of UDP datagrams emitted per logical publish. `1` = no retransmission. First send is synchronous; the rest run on a per-publish goroutine. **`-1`** = indefinite: keep retransmitting at `retransmit_delay` until another publish for the same topic supersedes it (requires `retransmit_delay >= 1s`). |
| `mpubsub` | `retransmit_delay` | `100ms` | Spacing between successive sends. Go duration string (`"100ms"`, `"1s"`, `"0s"`). `0` supported for finite counts. |
| `mpubsub` | `promote_qos` | `false` | When true, the incoming MQTT QoS bumps the effective retransmit_count: QoS 0 unchanged, QoS 1 → `max(retransmit_count, 3)`, QoS 2 → `-1` (indefinite). |
| `mpubsub` | `interface` | (kernel default) | Egress interface name (`eth0`, `br-lan`, …). |
| `mpubsub` | `encryption.key` | — | Optional XXTEA-256 passphrase, SHA-256'd to a 32-byte key. Must match the ESPHome devices' `mpubsub.encryption.key`. Enables encrypting outbound `mqtt_to_mpubsub` traffic and decrypting inbound `mpubsub_to_mqtt` traffic. |
| `mpubsub` | `encryption.replay_window` | — | Optional Go duration (e.g. `30s`). When set, outbound encrypted publishes are stamped with the bridge clock + a random nonce, and inbound encrypted packets that are stale or repeat a recently-seen nonce are dropped. Mirrors the ESPHome devices' `mpubsub.encryption.replay_window`; requires `encryption.key`. |
| `bridges[]` | `direction` | — | `mqtt_to_mpubsub` or `mpubsub_to_mqtt`. One-directional. |
| `bridges[]` | `mqtt_topic` | — | The MQTT topic to subscribe to (mqtt→mpubsub) or publish to (mpubsub→mqtt). MQTT wildcards (`+`, `#`) are accepted on `mqtt_to_mpubsub` entries. |
| `bridges[]` | `mpubsub_topic` | — | The mpubsub topic. Required for `mpubsub_to_mqtt`. On `mqtt_to_mpubsub`, optional: omit to forward each MQTT message under its **resolved** topic (the `msg.Topic()` from the broker), which is what makes MQTT wildcards useful — each match keeps its identity instead of being collapsed onto one multicast group. mpubsub itself has no wildcard subscriptions, so wildcards are rejected here. |
| `bridges[]` | `require_encryption` | `false` | Only valid on `mpubsub_to_mqtt` entries: drop plaintext datagrams for this mpubsub topic instead of forwarding them to MQTT. Requires `mpubsub.encryption.key`. |

## Notes

- **Wire format**: this binary embeds a Go reimplementation of the same wire
  format used by the C++ component (`components/mpubsub/`) and the
  Python reference (`tests/unit/reference.py`). If you change one, change all
  three.
- **Encoding**: outgoing packets are sent as `ENCODING=RAW` (opaque MQTT
  payload bytes). Incoming `ENCODING=PROTOBUF` packets are dropped on the
  multicast→MQTT side because the bridge has no way to know which protobuf
  schema the bytes belong to. Use raw publishes if you need MQTT bridging.
- **Loops**: each bridge entry is one-directional by design. If you bridge
  the same topic both ways through a broker that re-delivers to its
  publisher you can create a feedback loop -- use distinct `mqtt_topic`
  names on the two sides, or be very careful with retained/QoS settings.
- **Loopback**: the multicast socket has `IPV6_MULTICAST_LOOP=1`, so a
  second bridge or a probe co-located on the same host can receive the
  bridge's outbound publications. Because each bridge entry is
  one-directional, the bridge re-receiving its own packet does not feed
  back into the inbound MQTT subscription -- it would only matter if you
  configured a third route looping the destination MQTT topic back into
  the same multicast topic.
