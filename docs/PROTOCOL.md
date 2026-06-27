# Protocol specification (v1)

This document is the authoritative wire-protocol reference for
`mpubsub`. The Python reference implementation in
[`tests/unit/reference.py`](../tests/unit/reference.py) is the executable
ground truth; the C++ implementation in
[`components/mpubsub/`](../components/mpubsub/) is verified
to match it byte-for-byte by [`tests/unit/test_topic_hash_cpp.py`](../tests/unit/test_topic_hash_cpp.py)
and [`tests/unit/test_wire_format_cpp.py`](../tests/unit/test_wire_format_cpp.py).

If a sentence in this document and a behavior in `reference.py` disagree,
`reference.py` wins and this document is wrong — please open a PR.

## 1. Transport

* **Protocol:** UDP/IPv6.
* **Port:** default `18512`, configurable. Both publisher and subscriber
  must use the same port. Chosen to sit one above the existing ESPHome
  `udp:` / `packet_transport:` default of 18511 (no IANA assignment in
  that neighborhood, no conflict with CoAP / mDNS).
* **Datagram size:** maximum **1232 bytes** end-to-end. This is IPv6's
  minimum-MTU UDP payload: 1280 byte IPv6 minimum MTU (RFC 8200 §5) minus
  the 40-byte IPv6 header and the 8-byte UDP header. Every RFC-compliant
  IPv6 link is required to carry this size without fragmentation.

## 2. Topic → multicast group derivation

Each topic deterministically maps to a single IPv6 multicast group address:

```
group = 0xFF || 0x1<scope> || SHA-256(utf8(topic))[0..14]
```

| Bits      | Field                | Value                                       |
|-----------|----------------------|---------------------------------------------|
| 0..7      | Multicast prefix     | `0xFF` (IPv6 multicast)                     |
| 8..11     | Flags nibble (`T=1`) | `0x1` (transient, per RFC 4291 §2.7)        |
| 12..15    | Scope nibble         | `0x2`, `0x5`, or `0x8` (see §2.1)           |
| 16..127   | Topic hash           | `SHA-256(utf8(topic))[0..14]` (112 bits)    |

The 112-bit topic hash matches the original disclosure exactly. Truncating
SHA-256 is safe for hash-table-style mapping: birthday-style collisions
require ~`2^56` distinct topics on a single network, which is far beyond
realistic.

We use SHA-256 truncated to 14 bytes rather than a native-128-bit hash
(xxHash3, MurmurHash3, etc.). Truncated SHA-2 is explicitly permitted by
NIST (FIPS 180-4 §7); SHA-224 and SHA-384 are formal examples of the same
pattern. Picking a hash we already ship gives us one vendored
implementation rather than two, and the speed/flash overhead is small
enough not to matter at one hash per `subscribe` / `publish` call.

### 2.1 Scopes

| Name                 | Nibble | Address prefix | Travels over                                  |
|----------------------|:------:|----------------|-----------------------------------------------|
| `link-local`         | `0x2`  | `ff12::/16`    | A single L2 segment / VLAN. **Default.** Not forwarded by routers. |
| `site-local`         | `0x5`  | `ff15::/16`    | A single administrative site, requires MLD-snooping for VLAN-crossing. |
| `organization-local` | `0x8`  | `ff18::/16`    | Bridged sites with multicast routing config.  |

Choose the smallest scope that covers all participating devices. A smaller
scope reduces the multicast routing surface area and bandwidth across
uninvolved switches.

### 2.2 Worked example

```
topic = "home/livingroom/temp"
sha256(b"home/livingroom/temp") = e7e87b62 a3d2a7c2 ...    (32 bytes)
take first 14 bytes               e7e87b62 a3d2a7c2 ...    (the hash bits)
prefix                            ff12:                    (link-local)
result                            ff12:e7e8:7b62:a3d2:a7c2:...
```

The canonical fingerprint for this topic on a link-local network is:

```
[ff12:e7e8:7b62:a3d2:a7c2:...]:18512
```

Use `python3 tests/probe.py --topic 'home/livingroom/temp' --scope link-local`
to compute it locally; the probe prints the group address as it starts.

## 3. Packet format

```
 byte:  0    1    2    3    4    5    6    7    8    9   10   11   12 ...
       +----+----+----+----+----+----+----+----+----+----+----+----+----+
       | 'M'| 'P'| VER| ENC|        TOPIC_CRC32         | PAY_LEN  |ENM | RSV | BODY ...
       +----+----+----+----+----+----+----+----+----+----+----+----+----+
```

Total: **12-byte header + up to 1220 bytes body = 1232-byte datagram.**

| Offset | Size | Field        | Notes                                                          |
|-------:|-----:|--------------|----------------------------------------------------------------|
|      0 |    2 | `MAGIC`      | ASCII `"MP"` (`0x4D 0x50`)                                     |
|      2 |    1 | `VERSION`    | `0x01`                                                         |
|      3 |    1 | `ENCODING`   | Body-encoding enum (see §3.1)                                  |
|      4 |    4 | `TOPIC_CRC32`| Little-endian CRC-32/IEEE 802.3 of the UTF-8 topic string. When `ENC_MODE != 0` this field is zero and the real CRC lives in the ciphertext (see §3.3). |
|      8 |    2 | `PAYLOAD_LEN`| Little-endian uint16; the **plaintext** payload length. For `ENC_MODE == 0` it equals `len(datagram) - 12`; for `ENC_MODE == 1` it is the user payload size and the on-wire body is longer (see §3.3). |
|     10 |    1 | `ENC_MODE`   | Encryption mode enum (see §3.3). `0x00` = plaintext (default). |
|     11 |    1 | `RESERVED`   | Senders MUST write `0x00`. Receivers MUST ignore.              |
|     12 | ≤1220| `BODY`       | Encoding-dependent (see §3.1) and possibly XXTEA-encrypted (see §3.3). |

### 3.1 ENCODING byte and body layout

Byte 3 is a 1-byte enum indicating how the body should be parsed:

| Value      | Name        | Body layout                                                   |
|-----------:|-------------|---------------------------------------------------------------|
| `0x00`     | `RAW`       | Opaque bytes. The application interprets them however it likes. |
| `0x01`     | `PROTOBUF`  | 2-byte little-endian `SCHEMA_ID` followed by protobuf bytes.  |
| `0x02..FF` | reserved    | Receivers MUST drop the packet. Reserved for future encodings such as compression flavors. |

**`RAW` body:**
```
[12-byte header][opaque bytes (PAYLOAD_LEN total)]
```

**`PROTOBUF` body:**
```
[12-byte header][SCHEMA_ID: uint16 LE][protobuf bytes]
```
where `PAYLOAD_LEN = 2 + len(protobuf bytes)`.

The `SCHEMA_ID` is the low 16 bits of CRC-32 over the **canonical
schema string**: fields sorted by tag, each rendered as
`<tag>:<type>:<name>` (no whitespace; repeated fields render as
`<tag>:repeated <type>:<name>`), lines joined with `\n`, UTF-8.
Two devices declaring an identical schema produce the same id;
changing any field's name/type/tag/repeated-ness changes the id. A
receiver MUST drop a `PROTOBUF` packet whose `SCHEMA_ID` doesn't match
any typed subscriber on the topic.

Protobuf body bytes are produced by ESPHome's
`esphome::api::ProtoEncode` primitives (the same library the native
API uses), so on-wire output is byte-for-byte identical to other
protobuf implementations supporting wire types 0, 2, and 5. Wire type
1 (64-bit fixed: `double`, `fixed64`, `sfixed64`) is **intentionally
unsupported** — matches the upstream encoder, which omits it to save
flash on 32-bit microcontrollers.

Two ways to generate the protobuf body in firmware:

* **Codegen-generated `encode_to(...)`** on each typed struct
  (declared via YAML `messages:`).
* **`DynamicMessage`** — fluent runtime builder for bridges and any
  forwarder that decides field shape at runtime.

Both are bit-for-bit compatible; see [`CXX_API.md`](CXX_API.md).

### 3.2 TOPIC_CRC32

The CRC is computed over the UTF-8 bytes of the topic string, **not** the
topic hash; it's identical to `zlib.crc32(topic.encode("utf-8"))` and the
ESPHome `esphome::crc32()` helper.

It exists to disambiguate the (vanishingly rare) case where two different
topics map to the same 112-bit IPv6 group: a subscriber that joined group
G because it cares about topic A will receive a datagram for unrelated
topic B if some publisher elsewhere maps B onto the same G. The receiver
compares the incoming `TOPIC_CRC32` to the CRC32 of every topic it has
subscribed to; on mismatch it silently drops the datagram.

A 112-bit address hash plus a 32-bit topic CRC means a false positive
requires colliding 144 bits, well above any conceivable network's
collision floor.

### 3.3 ENC_MODE byte and optional payload encryption

Byte 10 is a 1-byte enum signalling whether the body has been encrypted:

| Value      | Name     | Body layout                                                       |
|-----------:|----------|-------------------------------------------------------------------|
| `0x00`     | `NONE`   | Plaintext (default; the body is exactly the §3.1 layout).         |
| `0x01`     | `XXTEA`  | XXTEA-256 ciphertext over a 12-byte prefix followed by the plaintext payload: `[TOPIC_CRC32 LE (4)] || [TIMESTAMP LE (4)] || [NONCE LE (4)] || payload`, zero-padded up to `roundup4(12 + PAYLOAD_LEN)` bytes. The 12-byte prefix already exceeds XXTEA's 2-word (8-byte) minimum, so no separate floor is needed. |
| `0x02..FF` | reserved | Receivers MUST drop.                                              |

The prefix carries three fields ahead of the user payload:

* **`TOPIC_CRC32`** — the integrity tag (see "Integrity check" below).
* **`TIMESTAMP`** — unix epoch seconds at send time, or `0` if the sender
  has no synchronized clock. Drives the receiver's freshness check.
* **`NONCE`** — 4 random bytes per message. Gives every publication a
  distinct identity even when two payloads are byte-identical, and is the
  key the receiver de-duplicates on. A retransmit (`retransmit_count > 1`)
  re-sends the same datagram and so reuses its nonce, which lets the
  receiver collapse retransmits to a single delivery.

**Key derivation.** The 32-byte XXTEA-256 key is `SHA-256(passphrase)`,
identical to the convention `packet_transport` uses for its
`encryption.key` option. Configure once on every participating node:

```yaml
mpubsub:
  encryption:
    key: "any-length passphrase"
```

The C++ implementation reuses ESPHome's `esphome::xxtea::encrypt`/`decrypt`
helpers (which `packet_transport` already vendored), so the on-wire bytes
are byte-for-byte compatible with that algorithm.

**Integrity check.** There is no separate MAC. The integrity tag is the
`TOPIC_CRC32` carried at the start of the ciphertext: a wrong key produces
a random 32-bit value that with probability `1 − 2⁻³²` won't match any
subscribed topic, so the packet is silently dropped at dispatch (§4 rule
6). The cleartext header's `TOPIC_CRC32` field (bytes 4–7) is forced to
zero when `ENC_MODE != NONE` to avoid leaking the topic identity to a
passive observer.

**Mixed-mode deployments.** Receivers that have an encryption key
configured accept both `ENC_MODE = NONE` and `ENC_MODE = XXTEA` packets —
the decoder picks the path from the header byte. Receivers without a key
configured drop encrypted packets. Individual subscriptions can opt in to
encryption-only mode by setting `require_encryption: true` on an
`on_message:` entry or on a `sensor: platform: mpubsub` block; plaintext
datagrams for that topic are then dropped at dispatch regardless of what
other subscribers want.

**Replay protection (optional).** A captured XXTEA datagram is byte-identical
however long after it was recorded, so anyone off the L2 segment can resend
it. Enabling a freshness window turns the in-ciphertext `TIMESTAMP` + `NONCE`
into replay rejection, with **no persistent state and no inter-node
coordination** — the only shared reference is the externally-synced wall
clock, which a node re-fetches over NTP/Home-Assistant time within seconds of
every boot:

```yaml
mpubsub:
  encryption:
    key: "any-length passphrase"
    replay_window: 30s     # enables replay protection
    time_id: my_time       # a time: component to clock freshness against
```

The receiver applies two layers:

1. **Freshness window.** Drop any packet whose `TIMESTAMP` is more than
   `replay_window` seconds from the receiver's own clock. The timestamp lives
   inside the ciphertext, so an attacker without the key cannot move it
   without breaking the CRC — they can only resend a verbatim copy, which the
   window confines to a short tail.
2. **Nonce de-duplication.** Within that window the receiver remembers the
   nonces it has recently seen (a bounded ring, so RAM stays fixed on
   ESP8266-class devices) and drops repeats.

The guard **fails closed**: while protection is on, a packet with
`TIMESTAMP == 0` (the sender had no synced clock) or a receiver whose own
clock has not yet synced is rejected, never silently admitted. The cache may
be empty after a reboot — harmless, because layer 1 already rejects anything
older than the window. This defends against any attacker **without** the key;
a key-holder can still mint fresh packets, which replay protection alone
cannot stop (see authentication, below).

**Security caveats.** Even with replay protection on, this scheme provides
**confidentiality and weak integrity** within the threat model of "passive
eavesdroppers and unkeyed attackers". It does **not** provide:

* **Forward secrecy** — the key is long-lived; capture-now-decrypt-later
  is feasible if the passphrase later leaks.
* **Strong authentication** — the topic CRC is a 32-bit tag and would be
  trivial to forge by an attacker who knows the key. Treat encryption
  as an obfuscation layer for adversaries off the L2 segment, not as a
  full authenticated-encryption scheme.

If either of those matters for your deployment, layer a real AEAD inside the
payload (e.g. a libsodium `crypto_secretbox` blob in `RAW` mode) or run
the protocol on an isolated/encrypted L2 (e.g. WireGuard).

## 4. Validation rules

A receiver MUST silently drop a datagram (and SHOULD `ESP_LOGV` the
reason) if any of the following is true:

1. `len(datagram) < 12` — header truncated.
2. `datagram[0..2] != b"MP"` — bad magic.
3. `datagram[2] != 0x01` — unknown version.
4. `datagram[3]` is not a known encoding value (`0x00` or `0x01`) — unknown encoding.
5. `datagram[10]` is not a known ENC_MODE value (`0x00` or `0x01`) — unknown enc_mode.
6. For `ENC_MODE == 0x00`: `12 + PAYLOAD_LEN != len(datagram)` — length mismatch.
   For `ENC_MODE == 0x01`: `len(datagram) != 12 + roundup4(12 + PAYLOAD_LEN)` — ciphertext length mismatch.
7. `ENC_MODE == 0x01` but no encryption key is configured on this receiver.
8. The recovered `TOPIC_CRC32` (header field for plaintext, first 4 bytes of decrypted plaintext for encrypted) matches none of the topics this node has subscribed to.

A receiver with replay protection enabled (a configured `replay_window`)
additionally drops an `ENC_MODE == 0x01` datagram, **after** decryption, if
its recovered `TIMESTAMP` is more than the window from the local clock, if
the local clock is unsynced, if `TIMESTAMP == 0`, or if its `NONCE` was
already seen within the window (§3.3). This is receiver-side policy, not a
wire-validity rule — an unprotected receiver accepts the same datagram.

For `ENCODING == PROTOBUF` packets, the receiver additionally MUST
drop the body if:

9. `PAYLOAD_LEN < 2` — body too short to carry a `SCHEMA_ID`.
10. The `SCHEMA_ID` doesn't match any typed subscriber on the topic.

The C++ implementation surfaces (1)–(6) as a `DecodeError` enum
(`TOO_SHORT`, `BAD_MAGIC`, `BAD_VERSION`, `UNKNOWN_ENCODING`,
`UNKNOWN_ENC_MODE`, `LENGTH_MISMATCH`, `CIPHERTEXT_TOO_SHORT`); (7)–(10)
are post-decode filtering in `MulticastPubSub::on_packet_` /
`MulticastPubSub::deliver_`. See `components/mpubsub/wire_format.h`.

## 5. Sender requirements

A publisher MUST:

* Reject a payload larger than **1220 bytes**. The Python codegen for the
  `mpubsub.publish:` action rejects literal payloads above that
  size at config time. The runtime rejects oversize lambda payloads at
  `publish()` time and logs an `ERROR`.
* Set `ENCODING` to one of the defined values (`0x00 = RAW`, `0x01 =
  PROTOBUF`). Reserved values are forward-compat slots and MUST NOT
  appear in current traffic.
* For `ENCODING == PROTOBUF`, prepend the 2-byte little-endian
  `SCHEMA_ID` before the protobuf bytes; `PAYLOAD_LEN` counts the
  schema id plus the protobuf body.
* Set `RESERVED` bytes (offsets 10–11) to `0x00 0x00`.
* Use the same UDP port the subscribers are listening on (default 18512).
* Set IPv6 multicast hop limit (`IPV6_MULTICAST_HOPS`). The component
  defaults to `1` (one hop, so the datagram never leaves the local link);
  raise it via the `hops:` YAML option if you need cross-subnet delivery
  with a wider scope.

## 6. Receiver requirements

A subscriber MUST:

* Bind a UDP/IPv6 socket to `[::]:port`.
* Set `SO_REUSEADDR` (so multiple subscribers can coexist on one host).
* For each subscribed topic, `setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, ...)`
  with the topic's derived group address.
* On each received datagram, run the validation rules in §4. On success,
  deliver the payload to every callback registered for the matching topic.

## 7. Out of scope (v1)

The following are **not** part of this protocol revision. A v2 may add
them; if so it will bump `VERSION` to `0x02`.

* **Forward secrecy.** The optional XXTEA-256 payload encryption (§3.3) is a
  long-lived shared key, so an attacker who later learns the key can decrypt
  previously-captured traffic. (Replay protection against non-key-holders
  *is* available via the optional `replay_window`; see §3.3. Full
  authenticated encryption is still out of scope — layer a real AEAD inside
  the payload or run the protocol on an isolated/encrypted L2 such as
  WireGuard.)
* **MQTT-style wildcards.** Each subscription is one exact topic. Bridges
  (see [`examples/05_mqtt_bridge.yaml`](../examples/05_mqtt_bridge.yaml))
  can fan out wildcards on the broker side.
* **Retain / Last Will.** Multicast UDP is fire-and-forget. The
  `FLAG_RETAIN_HINT` bit is a hint for bridges, nothing more.
* **Acknowledgements.** No `PUBACK`-equivalent.
* **IPv4.** Defining an mDNS-coordinated IPv4 mapping (per the original
  disclosure) is left to a future version. Right now IPv4-only networks
  cannot participate.
* **Fragmentation.** A single publication is a single datagram; if your
  payload won't fit in 1220 bytes, chunk it at the application layer.

## 8. Differences from the original disclosure

The protocol implemented here is a concrete refinement of the
self-organizing publish/subscribe disclosure (Genera, Technical Disclosure
Commons Art. 5601, 2022). Specific choices made here that the disclosure
left open:

* **Hash function:** SHA-256 (truncated to 112 bits) — chosen for
  ubiquitous availability and good distribution.
* **Header layout:** the disclosure's Fig. 2 shows generic UDP fields
  (`SOURCE | DESTN | LENGTH | CHKSUM | PAYLOAD`) — the IP/UDP outer header
  — and notes that a topic CRC should be embedded "in the published
  message". We implement that as the 12-byte application-layer header
  documented here.
* **Default port:** 18512, picked to sit adjacent to ESPHome's existing
  `udp:` / `packet_transport:` default of 18511 — no IANA assignment in
  that neighborhood, no clash with CoAP (5683) or mDNS (5353).
* **Default scope:** link-local (`ff12::`), since it Just Works on every
  flat LAN without needing MLD-snooping configuration. Bump to
  `site-local` for multi-VLAN deployments.
