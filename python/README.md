# mpubsub (Python)

A pure-Python client and wire implementation for **mpubsub** — brokerless
publish/subscribe over IPv6 multicast, where each topic deterministically maps
to a multicast group. No broker, no bridge; peers on the same segment just hear
each other.

This is the standalone library extracted from the
[esphome-mpubsub](https://github.com/pgenera/esphome-mpubsub) project. It shares
its wire code, byte-for-byte, with the ESPHome C++ component, the Go MQTT
bridge, and the Home Assistant integration — so anything it sends, they decode,
and vice versa.

## Install

```bash
pip install "mpubsub @ git+https://github.com/pgenera/esphome-mpubsub.git#subdirectory=python"
```

The core is **stdlib-only** — it installs no dependencies and runs anywhere
Python 3.7+ does. For faster encryption (a C-backed ChaCha20-Poly1305, ~550×
the pure-Python fallback), add the `crypto` extra:

```bash
pip install "mpubsub[crypto] @ git+https://github.com/pgenera/esphome-mpubsub.git#subdirectory=python"
```

## Use

```python
import asyncio
from mpubsub import MpubsubClient

async def main():
    async with MpubsubClient(scope="link-local", key="shared-passphrase") as client:
        def on_temp(msg):
            print(msg.topic, msg.payload, "encrypted" if msg.was_encrypted else "")

        await client.subscribe("home/kitchen/temp", on_temp)
        client.publish("home/fan/cmd", "ON")
        await asyncio.sleep(3600)

asyncio.run(main())
```

`MpubsubClient` options mirror the ESPHome `mpubsub:` block and the Go bridge:
`port`, `scope` (`link-local`/`site-local`/`organization-local`), `interface`,
`key` (a passphrase, SHA-256'd to the key, or 32 raw bytes; omit for
plaintext), `hops`, `replay_window`, `retransmit_count`, `retransmit_delay`,
`promote_qos`.

- **`subscribe(topic, callback, encoding="utf-8")`** returns an unsubscribe
  callable. The callback gets a `Message` (`topic`, `payload`, `was_encrypted`,
  `wire_encoding`, `sender_timestamp`); it may be sync or `async`. `encoding=None`
  delivers raw `bytes`.
- **`publish(topic, payload, qos=0, retain=False)`** — `retain` is accepted and
  ignored (no wire equivalent); `qos` maps to retransmit count when
  `promote_qos` is set.

## Limitations

Inherited from the protocol: **no wildcards** (the wire carries a topic CRC32,
so `+`/`#` are rejected), **no retain**, **no QoS/acks**, **no discovery**, RAW
payloads only (typed/protobuf messages are device-to-device for now), and IPv6
multicast requires host networking. See the parent repo's
[`docs/PROTOCOL.md`](https://github.com/pgenera/esphome-mpubsub/blob/main/docs/PROTOCOL.md).

## Layout

- `mpubsub/wire.py` — framing, ChaCha20-Poly1305 AEAD, replay guard. A
  byte-identical copy of the protocol reference; a drift test in the parent
  repo fails if it diverges.
- `mpubsub/aio.py` — the asyncio transport (`MpubsubClient`).
