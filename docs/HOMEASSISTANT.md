# mpubsub for Home Assistant

A native Home Assistant integration that speaks mpubsub directly. No broker,
no bridge — Home Assistant joins the multicast groups itself and hears your
devices on the same segment.

Its API mirrors Home Assistant's built-in `mqtt` integration: the same
`async_publish` / `async_subscribe` signatures, the same entity config keys,
the same `ReceiveMessage` shape. Where mpubsub genuinely cannot do what MQTT
does, it says so loudly rather than silently doing nothing. **Read
[the caveats](#mqtt-vs-mpubsub) before porting an `mqtt:` block** — the
differences are real, and the first one will bite within a second of startup.

> Alternative: [`bridges/mqtt-go/`](../bridges/mqtt-go/) relays mpubsub to and
> from a real MQTT broker. Use that if you want a broker in the picture, or
> need MQTT wildcards, retain, or discovery. Use this if you want neither.

---

## Networking first — read this or nothing will work

mpubsub is IPv6 multicast. Home Assistant must be able to send and receive it
**on the same network segment as your devices**.

| Install method | Works? |
|---|---|
| Home Assistant OS / Supervised | Yes (host networking) |
| Home Assistant Container with `--network=host` | Yes |
| Home Assistant Core in a venv | Yes |
| **Home Assistant Container on the default bridge network** | **No — silently** |

The bridged-container case is the one to watch. The multicast group join
*succeeds* on the container's veth and no traffic ever arrives, so the
integration looks set up and simply never produces a value. There is no error
to find. If you are running HA Container, use `--network=host`.

Two more things that produce silence rather than errors:

- **The `scope:` must match your devices.** A different scope nibble is a
  *different multicast group address*, so a `site-local` Home Assistant will
  not hear a `link-local` device at all. Both default to `link-local`; leave
  them alone unless you have actually deployed multicast routing.
- **The `port:` must match too**, for the same reason.

On a host with more than one network interface, set `interface:`. One socket
joins one link, so without it the kernel picks — possibly the wrong one.
(Loopback is never a valid choice: `lo` has no link-local address and so no
multicast route.)

---

## Install

**HACS** → three-dot menu → Custom repositories → add this repo as an
*Integration*, then install and restart.

**Manually**: copy `custom_components/mpubsub/` into your config directory's
`custom_components/` and restart.

The integration has **no Python dependencies** — it vendors the protocol
reference, which is pure standard library. (It uses `cryptography` to
accelerate the AEAD when it's importable, which it always is under Home
Assistant, and falls back to pure Python when it isn't.)

Then **Settings → Devices & Services → Add Integration → mpubsub**.

Developed and tested against **Home Assistant 2026.7**. The `2024.12.0`
minimum in `hacs.json` is inferred from the newest API it touches, not
verified — if you run something older and it breaks, that's why.

### Connection options (config entry)

Set at add time; change under *Configure*. These mirror the ESPHome
component's ([docs/CONFIG.md](CONFIG.md)) and the Go bridge's option names.

| Option | Default | Notes |
|---|---|---|
| `port` | `18512` | Must match your devices. |
| `scope` | `link-local` | `link-local`, `site-local`, `organization-local`. Must match your devices. |
| `interface` | *(kernel picks)* | Effectively required with >1 NIC. |
| `encryption_key` | *(none)* | The passphrase from your devices' `encryption: key:`. Blank = plaintext. |
| `hops` | `1` | Multicast hop limit. 1 keeps traffic local. |
| `retransmit_count` | `1` | Datagrams per publish. `-1` = resend until superseded (needs `retransmit_delay` ≥ 1s). |
| `retransmit_delay` | `0.1` | Seconds between retransmissions. |
| `promote_qos` | `false` | See [QoS](#qos-and-retain). |
| `replay_window` | `0` | Seconds of clock skew accepted on **encrypted** packets; also the nonce de-dup horizon. `0` disables. |

---

## Entities (YAML)

The `mpubsub:` key carries **entity config only** — the connection lives in
the config entry. This is the same split `mqtt:` uses.

```yaml
mpubsub:
  sensor:
    - name: "Garage temperature"
      unique_id: garage_temp
      state_topic: "home/garage/temp"
      unit_of_measurement: "°C"
      device_class: temperature
      state_class: measurement
      expire_after: 120        # strongly recommended — see below

  binary_sensor:
    - name: "Garage door"
      unique_id: garage_door
      state_topic: "home/garage/door"
      device_class: door
      payload_on: "OPEN"
      payload_off: "CLOSED"

  switch:
    - name: "Garage fan"
      unique_id: garage_fan
      command_topic: "home/garage/fan/set"
      state_topic: "home/garage/fan/state"
```

Supported keys are `mqtt`'s, spelled identically:

- **common** — `name`, `unique_id`, `icon`, `entity_category`,
  `enabled_by_default`, `device`, `qos`, `encoding`, `value_template`,
  `availability_topic`, `availability_template`, `payload_available`,
  `payload_not_available`
- **sensor** — `state_topic` (required), `unit_of_measurement`,
  `device_class`, `state_class`, `suggested_display_precision`,
  `expire_after`, `force_update`
- **binary_sensor** — `state_topic` (required), `payload_on`, `payload_off`,
  `device_class`, `off_delay`, `expire_after`, `force_update`
- **switch** — `command_topic` (required), `state_topic`, `payload_on`,
  `payload_off`, `state_on`, `state_off`, `optimistic`, `device_class`,
  `retain` *(ignored)*

`unique_id` is not optional in practice: without one an entity can't be
renamed, placed in an area, or customised in the UI. There is no discovery to
supply one, and deriving it from the topic would be wrong (it would collide
between two entities on one topic, and change if you renamed the topic,
orphaning the registry entry). You get a warning if you omit it.

### Why every entity starts `unknown`

**This is the difference you will notice first.** MQTT hands an entity its
last value at startup from the broker's retained message. mpubsub has no
broker and no retain, so **there is nothing to replay** — an entity is
`unknown` until a packet arrives. For a 1 Hz sensor that is a second. For a
doorbell that publishes only when pressed, it is however long until someone
presses it.

Consequences worth planning around:

- **Use `expire_after` on every sensor.** It is not a nicety here: there is
  no last will, so nothing announces a dead publisher. It is the only
  liveness signal available.
- **`availability_topic` is one-directional.** A device can announce
  `online`; nothing can announce its death on its behalf. Alone, it makes an
  entity available *forever* after the first message. Always pair it with
  `expire_after`.
- **An optimistic switch's state does not survive a restart** and cannot be
  recovered.
- Prefer publishing **periodically** over publishing only on change.

---

## Services

### `mpubsub.publish`

```yaml
action: mpubsub.publish
data:
  topic: home/garage/fan/set
  payload: "ON"
```

Fields: `topic`, `payload`, `evaluate_payload` (parse the payload as a Python
literal, so `b'\x01'` works), `qos`, `retain`.

### `mpubsub.listen` — the debug tool

Home Assistant's MQTT troubleshooting panel is hardcoded in the frontend to
the `mqtt` domain, so a custom integration cannot reuse it. `mpubsub.listen`
gives you the same thing through **Developer Tools → Actions**:

```yaml
action: mpubsub.listen
data:
  topic: home/garage/temp
  duration: 30
```

It returns what it heard, inline:

```yaml
messages:
  - topic: home/garage/temp
    payload: "21.5"
    was_encrypted: true
    sender_timestamp: 1763251200
count: 1
```

Each message is also fired on the event bus as **`mpubsub_message_received`**,
so **Developer Tools → Events** can watch it live, and automations can trigger
on it.

`count: 0` is a real answer: nothing is publishing on that topic, or you
can't hear it (see [Networking](#networking-first--read-this-or-nothing-will-work)).

There is no `mqtt.dump` equivalent — that needs a `#` subscription. Outside
Home Assistant, [`tests/probe.py`](../tests/probe.py) does the same job:

```bash
python3 tests/probe.py --listen --topic home/garage/temp
```

---

## Python API

For `python_script`s, AppDaemon, or another integration:

```python
from custom_components.mpubsub import async_publish, async_subscribe

await async_publish(hass, "home/fan/cmd", "ON")

@callback
def handle(msg):
    _LOGGER.info("%s -> %s (encrypted=%s)", msg.topic, msg.payload, msg.was_encrypted)

unsub = await async_subscribe(hass, "home/kitchen/temp", handle)
```

Signature-identical to `homeassistant.components.mqtt`:

| Function | Difference |
|---|---|
| `async_publish(hass, topic, payload, qos=0, retain=False, encoding="utf-8")` | `retain` ignored; `qos` → retransmits; raises on wildcards and oversize payloads |
| `async_subscribe(hass, topic, msg_callback, qos=0, encoding="utf-8")` | `qos` ignored; raises on wildcards; awaits a real group join, so it can raise `OSError` |
| `publish(...)` | sync wrapper |
| `async_wait_for_client(hass)` | the `async_wait_for_mqtt_client` analogue |

`ReceiveMessage` keeps `mqtt`'s six fields in its order — `topic`, `payload`,
`qos`, `retain`, `subscribed_topic`, `timestamp` — so a callback lifted from
an MQTT setup keeps working. `qos` is always `0` and `retain` always `False`
(no wire fields), and `subscribed_topic` always equals `topic` (in MQTT they
differ only under wildcards). Three mpubsub-only fields follow:
`was_encrypted`, `wire_encoding`, `sender_timestamp`.

Note `encoding` here is the **text codec** for the payload (`None` gives you
`bytes`). The wire's ENCODING byte is a different thing, exposed as
`wire_encoding`.

---

## MQTT vs mpubsub

| MQTT feature | mpubsub | What to do instead |
|---|---|---|
| Broker | None. Peer-to-peer UDP multicast. | Nothing to install, nothing to fail. |
| Wildcards `+` / `#` | **Rejected with an error.** The wire carries only a CRC32 of the topic, and receiving means joining the group derived from the exact string — there is nothing to match a pattern against. | Enumerate topics. Or use the Go bridge to fan out from a real broker. |
| Discovery | **Not supported, by design.** It needs a wildcard subscription. | Declare entities in YAML. |
| Retain | **Ignored** (accepted on publish for compatibility). | Entities start `unknown`. Use `expire_after`; publish periodically. |
| QoS | No wire field. With `promote_qos`, maps to retransmits. | Raise `retransmit_count` for messages that matter. |
| Last will / birth | None. | `availability_topic` + `expire_after`. It can only ever say "online". |
| Acknowledgements | None. Fire-and-forget UDP. | Retransmits improve the odds; nothing makes delivery certain. |
| Duplicate delivery | Encrypted + `replay_window > 0`: retransmits de-dup by nonce. **Plaintext: a `retransmit_count: 3` publish is delivered 3 times.** | Idempotent handlers, or encryption + `replay_window`. |
| Ordering | None. | Don't rely on it. |
| `mqtt.dump` | No equivalent (needs `#`). | `mpubsub.listen`, or `tests/probe.py --listen`. |
| Max payload | 1220 bytes; 36 fewer when encrypted. | Split, or don't. |
| Max topic length | 200 bytes, non-empty, no NUL. | Same rule as the ESPHome side. |
| Auth / ACL | None. One shared key, or plaintext. Any key-holder can forge. | Encrypt, and treat the segment as the trust boundary. |
| Typed / protobuf messages | Not supported yet (RAW only). | ESPHome device-to-device, or the Go bridge's `json_translation`. |

### A literal `+` or `#` in a topic

mpubsub itself allows them — the ESPHome validator says so explicitly. This
integration rejects them anyway, because someone writing against the MQTT API
who passes `home/+/temp` means a wildcard, and handing them a subscription
that silently never fires would be worse than an error. The cost: a literal
mpubsub topic containing `+` or `#` is unreachable from Home Assistant.

---

## Troubleshooting

**Nothing ever arrives.** In order: check the container is on host networking;
check `scope` and `port` match the devices; `mpubsub.listen` on a topic you
know is live; then `tests/probe.py --listen` from the same host to see whether
the packets are reaching the box at all.

**`Network is unreachable` when publishing.** No route for `ff12::/16` on the
chosen interface. Set `interface:` to a real one.

**Encrypted packets are dropped.** The passphrase must match exactly (it is
SHA-256'd to the key). If `replay_window > 0`, the sender's clock must be
within the window of Home Assistant's, and a device with no synced time stamps
`0` and is rejected by design.

**Duplicate state changes.** `retransmit_count > 1` without encryption. Turn
on encryption and set a `replay_window`, or set `retransmit_count: 1`.

Turn on debug logging to see every dropped packet and why:

```yaml
logger:
  logs:
    custom_components.mpubsub: debug
```
