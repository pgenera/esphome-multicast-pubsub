# Testing guide

This component ships **three layers** of tests, all runnable on Linux with
no microcontroller in sight. Each layer carries its own prerequisites and
skips cleanly without them; layer 1 in particular must keep running against
nothing but the standard library, so a stale dependency elsewhere can never
take the wire tests down with it.

## Layer 1 — unit tests (~3 seconds)

Tests under `tests/unit/` cover:

* Topic-hash and CRC32 derivation (Python reference + C++ binary
  cross-check).
* That `custom_components/mpubsub/reference.py` is still byte-identical to
  `tests/unit/reference.py` (`test_vendored_reference.py`). The Home
  Assistant component vendors the wire reference because it ships alone,
  with none of this repo around it; the copy is a copy, never a fork. Fix a
  failure with the one `cp` the message prints.
* ChaCha20-Poly1305 against **both** AEAD backends (`test_encryption.py`).
  `reference.py` uses `cryptography` when it can import it (550x faster, and
  the Home Assistant component decrypts on the event loop) and falls back to
  the pure-Python spec otherwise. The suite runs twice, forcing each path —
  the pure leg has to be forced, or it would silently stop being covered
  wherever `cryptography` is installed.
* Wire format encode/decode and every validation rule (Python +
  C++ binary).
* YAML schema acceptance and rejection via `esphome config`.

```bash
cd tests/unit
make            # builds two tiny C++ test harnesses
pytest -q
```

The C++ harnesses (`topic_hash_test`, `wire_format_test`) link only
`components/mpubsub/*.cpp` plus `topic_hash_main.cpp` /
`wire_format_main.cpp` — no ESPHome dependencies. This means the SHA-256,
topic-to-group, CRC32, header encode, and header decode code paths are
exercised against a Python reference (`tests/unit/reference.py`) for
byte-for-byte agreement.

### Adding new spec vectors

When you change the protocol, add a golden vector in
`tests/unit/test_topic_hash.py` (or `test_wire_format.py`) and re-run
`pytest`. The C++ cross-check tests will automatically extend coverage to
the new vector via the harness.

## Layer 2 — integration tests with `platform: host`

Run actual ESPHome firmware **as native Linux binaries**. The host
platform compiles to a regular `program` executable that uses BSD sockets,
so the C++ component runs end-to-end with real UDP packets over the
loopback interface.

```bash
esphome config tests/publisher.yaml      # validate
esphome config tests/subscriber.yaml
esphome compile tests/publisher.yaml     # build native binary
esphome compile tests/subscriber.yaml
```

### Manual end-to-end run

Three terminals:

```bash
# terminal 1 — subscriber
./tests/.esphome/build/pubsub-subscriber/.pioenvs/pubsub-subscriber/program

# terminal 2 — publisher
./tests/.esphome/build/pubsub-publisher/.pioenvs/pubsub-publisher/program

# terminal 3 — independent probe (uses tests/unit/reference.py for wire decode)
python3 tests/probe.py --topic test/temp --scope link-local --iface lo
```

Expected behavior within a few seconds:

* The subscriber logs `'Subscribed Temperature': Received new state
  NN.000000` once per second.
* The probe prints one captured frame per second, e.g.
  `crc=f7f84fca flags=01 payload(2 B)=3237 '27'`.

The probe is the **third independent implementation** of the wire format
(after C++ and `reference.py`). If all three agree, the protocol is
self-consistent.

### Why `--scope link-local` for local testing

`link-local` (`ff12::/16`) datagrams are delivered to every interface on
the host but never forwarded by a router. That makes them perfect for
two-process testing on a single Linux box: the kernel sees the publish on
the wifi/ethernet link-local address and delivers it to the subscriber
that joined the same group, even when both run on the same machine.

`site-local` may or may not work for inter-host testing depending on your
switch's MLD-snooping configuration. The default scope is `link-local` for
exactly this reason — it Just Works on flat LANs and loopback.

## Layer 3 — Home Assistant component tests

`tests/ha/` drives `custom_components/mpubsub/` inside a real Home Assistant,
over real IPv6 multicast. Home Assistant needs Python 3.14 and will not
install into a PEP 668 distro Python, so use a venv:

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r tests/ha/requirements.txt
.venv/bin/python -m pytest tests/ha        # from the repo root
```

`pytest-homeassistant-custom-component` pins an exact Home Assistant version
and releases weekly, so that pin goes stale on its own schedule; bump it when
`tests/ha` fails without a repo change. It cannot break layer 1.

The load-bearing one is `test_host_cross_check.py`, which puts the actual
ESPHome host binaries on the other end of a real multicast group in both
directions, plaintext and encrypted. Vendoring makes the wire bytes
undriftable; this covers everything vendoring can't — the scope nibble, the
port, the group join, the nonce reuse across retransmits. It needs the host
binaries built (layer 2) and skips otherwise. **The binaries can go stale
silently**: a subscriber compiled before the `verify_ok` counters existed
will fail the counter assertions for no reason visible in the diff. Rebuild
with `esphome compile` if a cross-check fails inexplicably.

Two environment notes worth knowing before debugging these:

* **`interface: lo` cannot work.** Loopback carries only `::1/128 scope
  host` with no link-local address, so it gets no `ff00::/8` route and a send
  to `ff12::` fails with `ENETUNREACH`. The tests let the kernel choose the
  interface — which is what `tests/probe.py` and the layer-1 cross-checks
  already do — so **running them emits a little real multicast on your LAN**
  (`hops: 1` keeps it on the segment).
* **The `freezer` fixture and real sockets don't mix.** A frozen clock stops
  `asyncio.sleep` advancing, so anything waiting on I/O hangs. The timer
  tests jump the scheduler with
  `async_fire_time_changed(hass, dt_util.utcnow() + delta)` instead.

## Compiling for real hardware

Once you've verified your changes pass both test layers, target a real
chip:

```bash
esphome compile examples/01_temperature_sensor.yaml
esphome upload examples/01_temperature_sensor.yaml --device /dev/ttyUSB0
```

The same component sources are used; only the platform-specific socket
backend changes (`bsd_sockets_impl.cpp` on host, LwIP-sockets on ESP-IDF).

## What's NOT covered yet

* No cross-VLAN / multi-host integration test. The `link-local` scope
  short-circuits this nicely on loopback, but verifying MLD-snooping
  forwarding requires a real switch.
* No fuzzing of the decode path. The decoder is small and exhaustively
  validated; fuzzing would still be a worthwhile addition.
* No memory benchmarking. Should be cheap (one socket, one `std::vector`
  per subscription) but unmeasured.
* No test of the Home Assistant component against the **Go bridge** on one
  fabric. Each is cross-checked against the C++ firmware, so they agree
  transitively, but the pair has never been run together.
* The Home Assistant component is not tested against any Home Assistant
  version other than the one `tests/ha/requirements.txt` currently pins.
