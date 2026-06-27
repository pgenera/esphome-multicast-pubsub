# How does this compare to MQTT / ESP-NOW / packet_transport?

`mpubsub` sits in a different design tradeoff space than the
existing ESPHome network components. None of these obsolete the others.

## vs. MQTT

|                       | `mqtt:`                            | `mpubsub:`                          |
|-----------------------|------------------------------------|----------------------------------------------|
| Topology              | Hub-and-spoke (clients ↔ broker)   | Peer-to-peer (every node ↔ every node)        |
| Broker required       | Yes                                | No                                            |
| Survives broker down  | No                                 | Yes                                           |
| Cloud reachability    | Required if broker is in cloud     | Not required                                  |
| Scope                 | Anywhere the broker is reachable   | A single IPv6 multicast scope (LAN / site)    |
| Wildcards             | Yes (`+`, `#`)                     | No (exact topic only)                         |
| Retain / Last Will    | Yes                                | No (hint flag exists for bridges)             |
| QoS levels            | 0, 1, 2                            | 0 only (UDP, no acks)                         |
| Authentication        | Username/password, TLS, mTLS       | None (relies on network isolation)            |
| Wire size overhead    | TCP + MQTT headers (~10–20 B)      | 12 B header                                   |
| Latency               | TCP handshake + broker hop         | One UDP datagram                              |
| Best for              | Cloud-integrated state, durable    | Brokerless LAN coordination, ephemeral state  |

**Use MQTT when:** you need durable state, you talk to Home Assistant or
similar, you cross the internet, you need authentication.

**Use `mpubsub` when:** the WAN can be down and devices must still
coordinate, broker setup is overkill, you want to fan a doorbell or motion
event out to N receivers without paying per-recipient broker cost.

**Use both, bridged**, when you want HA visibility for some topics but
graceful degradation if the broker dies — see
[`examples/05_mqtt_bridge.yaml`](../examples/05_mqtt_bridge.yaml).

## vs. ESP-NOW

ESP-NOW is a proprietary Wi-Fi MAC-layer protocol from Espressif. It
shares the brokerless property with `mpubsub` but differs in:

* **Hardware lock-in.** ESP-NOW only runs between Espressif chips. This
  component runs on anything that can speak UDP/IPv6: ESP32, ESP8266 (via
  LwIP), RP2040, host Linux, a Python script on your laptop.
* **Range.** ESP-NOW is point-to-point at the Wi-Fi MAC layer and can in
  principle reach further than the AP's coverage. `mpubsub` rides
  the regular L3 network, so range = whatever your IP infrastructure can
  cover.
* **Routing.** ESP-NOW won't cross a router. `mpubsub` will, with
  appropriate scope and MLD-routing configuration.
* **Topology.** ESP-NOW peering tables are O(peers). `mpubsub`
  has no peer table — joining a group is enough.
* **Discoverability.** A topic-hash address means anyone who knows the
  topic string can subscribe with zero coordination. ESP-NOW requires
  exchanging MACs.

## vs. ESPHome `udp:` + `packet_transport:`

The existing `udp:` / `packet_transport:` pair is the closest cousin. The
differences:

* **Topic semantics.** `packet_transport` is sensor-state-centric: every
  sensor configured on a device shares one broadcast/multicast group and
  is keyed by id within an opaque payload. `mpubsub` is
  topic-centric: each topic has its own multicast group, and the topic
  string is the address.
* **Subscription model.** With `packet_transport` you list **providers**
  (hostnames) you want sensors from. With `mpubsub` you list
  **topics** you care about, no matter who sends them.
* **Encryption / replay.** `packet_transport` includes XXTEA encryption and
  rolling codes against replay. `mpubsub` offers optional ChaCha20-Poly1305
  (authenticated; RFC 8439) with optional clock-based replay protection
  (`encryption.replay_window`) — see [`PROTOCOL.md`](PROTOCOL.md) §3.3. Both
  use a single shared key (no forward secrecy / per-peer identity).
* **API shape.** `packet_transport` plugs sensors and binary_sensors in;
  `mpubsub` also exposes `publish` / `on_message` MQTT-style
  primitives so it composes cleanly with non-sensor automations
  (doorbells, commands, etc.).
* **Address family.** `packet_transport`/`udp` is IPv4-only today.
  `mpubsub` is IPv6-only — at least for v1.

The two are complementary; pick whichever matches the data shape you're
moving around. For an arbitrary set of sensor.template values shared
between a small group of known devices, `packet_transport` is excellent.
For "anyone on this LAN who cares about doorbell events, here you go,"
`mpubsub` is a better fit.
