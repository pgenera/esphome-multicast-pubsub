# mpubsub — ESPHome external component

A brokerless publish/subscribe transport for ESPHome based on IPv6 multicast.
Each topic deterministically maps to an IPv6 multicast group; publishers send
UDP datagrams to the group and subscribers join it. No broker is needed, and
the protocol keeps working when the WAN or any cloud MQTT broker is
unreachable.

Based on the disclosure *Self-Organizing Publish/Subscribe on the Network
Edge* (Phil Genera, Technical Disclosure Commons Art. 5601, 2022). See the
PDF in this repository for background.

This component is **complementary to** ESPHome's existing `mqtt:` component —
both can be configured on the same device and bridged together; see
`tests/bridge_example.yaml`.

## Usage at a glance

Two big "modes" — pick whichever fits the data:

* **Raw payloads** — opaque bytes/strings. Cheapest, easiest, works
  without any extra dependencies. Best for booleans, short ASCII
  values, and one-shot events.
* **Typed protobuf messages** — declare a schema once, get a generated
  C++ struct with `encode_to` / `decode_from` and a fluent `Call`
  builder. Best for structured records (climate readings, doorbell
  events, anything with named fields).

Beyond ESPHome devices, two things can join a fabric:

* **Home Assistant, natively** — [`custom_components/mpubsub/`](custom_components/mpubsub/)
  is an integration that joins the multicast groups itself, with an API
  mirroring HA's built-in `mqtt`. No broker, no bridge. See
  [`docs/HOMEASSISTANT.md`](docs/HOMEASSISTANT.md).
* **An MQTT broker** — [`bridges/mqtt-go/`](bridges/mqtt-go/) relays both
  ways. Use this when you want a broker, MQTT wildcards, or discovery.

### Raw publish/subscribe (YAML)

```yaml
external_components:
  - source: { type: local, path: ../components }
    components: [mpubsub]

mpubsub:
  id: pubsub
  port: 18512            # default; one above ESPHome udp: default (18511)
  scope: link-local      # default; safest scope, works on any flat LAN
  on_message:
    - topic: "home/vacuum/done"
      then:
        - logger.log:
            format: "received: %s"
            args: ['std::string(x.begin(), x.end()).c_str()']

# Publish from any automation
on_...:
  - mpubsub.publish:
      topic: "home/vacuum/done"
      payload: !lambda 'return "1";'
```

### Sensor platform (auto-publish state, auto-update from received bytes)

```yaml
sensor:
  - platform: mpubsub
    topic: "home/livingroom/temp"
    name: "Living Room Temperature"
    # mode: subscribe (default) | publish
```

### Typed messages (YAML — declare + receive)

```yaml
api:                     # required when messages: is non-empty

mpubsub:
  id: pubsub
  messages:
    - id: room_climate
      fields:
        - { name: temperature, type: float,  tag: 1 }
        - { name: humidity,    type: float,  tag: 2 }
        - { name: room_id,     type: string, tag: 3 }
        - { name: tags,        type: string, tag: 4, repeated: true }
  on_message:
    - topic: "home/garage/climate"
      message: room_climate            # routes to the typed decoder
      then:
        - lambda: |-
            ESP_LOGI("climate", "%.1fC in %s",
                     x.temperature, x.room_id.c_str());
```

### Typed publish (C++ fluent builder, modeled on `LightCall`)

```yaml
on_value:
  - lambda: |-
      using esphome::multicast_pubsub::messages::RoomClimate;
      id(pubsub)->make_call<RoomClimate>("home/garage/climate")
          .set_temperature(x)
          .set_humidity(id(humidity).state)
          .set_room_id("garage")
          .add_tags("auto")
          .perform();
```

For everything else — schemaless `DynamicMessage` / `DynamicReader`,
`subscribe_typed<T>`, lifecycle, error handling — see
[`docs/CXX_API.md`](docs/CXX_API.md).

## Wire protocol (v1)

Each publication is a single UDP datagram (≤ 1232 bytes — IPv6's minimum-MTU UDP payload) sent to the topic's
multicast group on port 18512 (configurable).

### IPv6 multicast group derivation

```
group_addr = 0xFF || 0x1<scope> || SHA-256(utf8(topic))[0..14]
```

| Field            | Bits  | Value                                              |
|------------------|------:|----------------------------------------------------|
| Multicast prefix |     8 | `0xFF` (IPv6 multicast)                            |
| Flags nibble     |     4 | `0x1` (transient, RFC 4291 §2.7)                   |
| Scope nibble     |     4 | `0x2` link-local / `0x5` site-local / `0x8` org-local |
| Topic hash       |   112 | First 112 bits of `SHA-256(utf8 topic bytes)`      |

This yields exactly 112 bits of topic entropy per the spec.

### Header (12 bytes, little-endian)

```
 byte:  0    1    2    3    4    5    6    7    8    9   10   11
       +----+----+----+----+----+----+----+----+----+----+----+----+
       | 'M'| 'P'| VER| FLG|        TOPIC_CRC32         | PAY_LEN  | RSV
       +----+----+----+----+----+----+----+----+----+----+----+----+
```

| Offset | Size | Field        | Description                                        |
|-------:|-----:|--------------|----------------------------------------------------|
|      0 |    2 | MAGIC        | ASCII `"MP"` (`0x4D 0x50`)                         |
|      2 |    1 | VERSION      | Protocol version, `0x01` for v1                    |
|      3 |    1 | FLAGS        | bit 0 = text payload; bit 1 = retain hint; rest reserved |
|      4 |    4 | TOPIC_CRC32  | CRC-32/IEEE of the UTF-8 topic string, LE          |
|      8 |    2 | PAYLOAD_LEN  | uint16 LE; must equal `len(datagram) - 12`         |
|     10 |    2 | RESERVED     | Senders MUST write `0x00 0x00`; receivers MUST ignore (forward-compat) |
|     12 | ≤1220| PAYLOAD      | Opaque bytes                                       |

Receivers MUST drop the datagram silently if the magic is wrong, the version
is unknown, reserved flag bits are set, the length field is inconsistent, or
the `TOPIC_CRC32` doesn't correspond to any subscribed topic on the node
(handles the rare event of a 112-bit hash collision).

A reference implementation of encode/decode and the address derivation lives
in [`tests/unit/reference.py`](tests/unit/reference.py).

## Testing

```bash
# unit tests (pure Python; no ESPHome needed)
cd tests/unit && pytest -q

# config validation + host-platform compile
esphome config tests/subscriber.yaml
esphome compile tests/subscriber.yaml

# end-to-end smoke (two terminals)
./tests/run_e2e.sh

# Home Assistant component (needs a venv; see docs/TESTING.md)
.venv/bin/python -m pytest tests/ha
```

See `tests/README.md` for the full test catalog and
[`docs/TESTING.md`](docs/TESTING.md) for the three layers.

## License

MIT — see [`LICENSE`](LICENSE).

A note on the future direction: ESPHome itself dual-licenses C++ files
as GPLv3 and Python files as MIT. To keep the option open for an
upstream contribution to ESPHome's core down the road, the copyright
holder may relicense the C++ portions of this repository under GPLv3
at that time. The currently-released MIT terms remain in effect for
any code already distributed under them — re-licensing only applies
to future versions.

External contributors: please sign off your commits with `git commit
-s` (DCO) so the project can redistribute your patches under any
compatible license.

The spec PDF at the repository root is published separately by the
original author under CC BY 4.0; see the third-party notice at the
bottom of [`LICENSE`](LICENSE).

## Limitations (v1)

* IPv6 only. IPv4 / mDNS coordination is described in the spec but not yet
  implemented.
* Optional ChaCha20-Poly1305 payload encryption (authenticated; RFC 8439)
  with optional replay protection (`encryption.replay_window`, see
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §3.3). Single shared key, so no
  forward secrecy and any key-holder can forge traffic; for per-peer identity
  or key rotation run on an isolated/encrypted L2.
* No MQTT-style wildcards (`+`, `#`) — each subscription is one exact topic.
  A separate bridge can fan out wildcards from MQTT.
* No retain / last-will semantics; multicast UDP is fire-and-forget.
* The Home Assistant integration inherits every limitation above, and they
  are more visible there because MQTT sets a different expectation: entities
  start `unknown` (nothing retains a last value), wildcards are rejected
  outright, and there is no discovery. See the caveat table in
  [`docs/HOMEASSISTANT.md`](docs/HOMEASSISTANT.md). It is also RAW-only for
  now — typed messages are ESPHome-to-ESPHome.
