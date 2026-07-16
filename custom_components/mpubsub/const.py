"""Constants for the mpubsub integration.

Option names and defaults deliberately mirror the Go MQTT bridge
(``bridges/mqtt-go/config.go``) and the ESPHome component
(``components/mpubsub/__init__.py``) so one fabric can be described the same
way wherever it is configured. Where a value here disagrees with those, they
win -- a mismatched default is the worst kind of bug in this protocol,
because a different scope or port means a different multicast group and the
symptom is silence rather than an error.
"""

from __future__ import annotations

from homeassistant.const import Platform

from .reference import DEFAULT_PORT, SCOPE_LINK_LOCAL, SCOPE_ORG_LOCAL, SCOPE_SITE_LOCAL

DOMAIN = "mpubsub"

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]

# hass.data keys
DATA_MPUBSUB = DOMAIN
DATA_MPUBSUB_CONFIG = f"{DOMAIN}_config"

# Fired on the event bus by the mpubsub.listen debug service.
EVENT_MESSAGE_RECEIVED = "mpubsub_message_received"

# --- Config keys -------------------------------------------------------------
# entry.data (connection identity)
CONF_PORT = "port"
CONF_SCOPE = "scope"
CONF_INTERFACE = "interface"
CONF_ENCRYPTION_KEY = "encryption_key"

# entry.options (tuning)
CONF_HOPS = "hops"
CONF_RETRANSMIT_COUNT = "retransmit_count"
CONF_RETRANSMIT_DELAY = "retransmit_delay"
CONF_PROMOTE_QOS = "promote_qos"
CONF_REPLAY_WINDOW = "replay_window"

# Entity/platform keys (names match homeassistant.components.mqtt exactly)
CONF_STATE_TOPIC = "state_topic"
CONF_COMMAND_TOPIC = "command_topic"
CONF_AVAILABILITY_TOPIC = "availability_topic"
CONF_AVAILABILITY_TEMPLATE = "availability_template"
CONF_PAYLOAD_AVAILABLE = "payload_available"
CONF_PAYLOAD_NOT_AVAILABLE = "payload_not_available"
CONF_STATE_ON = "state_on"
CONF_STATE_OFF = "state_off"
CONF_EXPIRE_AFTER = "expire_after"
CONF_OFF_DELAY = "off_delay"
CONF_ENCODING = "encoding"
CONF_QOS = "qos"
CONF_RETAIN = "retain"
CONF_TOPIC = "topic"
CONF_PAYLOAD = "payload"
CONF_DURATION = "duration"
CONF_EVALUATE_PAYLOAD = "evaluate_payload"

# --- Defaults ----------------------------------------------------------------
# Every one of these is the Go bridge's / ESPHome's default. See config.go
# applyDefaults() and components/mpubsub/__init__.py's CONFIG_SCHEMA.
DEFAULT_SCOPE = "link-local"
DEFAULT_HOPS = 1
DEFAULT_RETRANSMIT_COUNT = 1
DEFAULT_RETRANSMIT_DELAY = 0.1  # seconds; Go's 100ms
DEFAULT_PROMOTE_QOS = False
DEFAULT_REPLAY_WINDOW = 0  # seconds; 0 disables replay protection
DEFAULT_QOS = 0
DEFAULT_ENCODING = "utf-8"
DEFAULT_PAYLOAD_AVAILABLE = "online"
DEFAULT_PAYLOAD_NOT_AVAILABLE = "offline"
DEFAULT_PAYLOAD_ON = "ON"
DEFAULT_PAYLOAD_OFF = "OFF"
DEFAULT_LISTEN_DURATION = 60  # seconds, for the mpubsub.listen debug service

# The same three scope names components/mpubsub/__init__.py:74-77 accepts.
SCOPES: dict[str, int] = {
    "link-local": SCOPE_LINK_LOCAL,
    "site-local": SCOPE_SITE_LOCAL,
    "organization-local": SCOPE_ORG_LOCAL,
}

# Retransmit count sentinel: keep emitting until a publish to the same topic
# supersedes it (bridges/mqtt-go/config.go, components/mpubsub/__init__.py:210).
RETRANSMIT_INDEFINITE = -1
# An indefinite chain needs non-trivial spacing or it saturates the segment.
MIN_INDEFINITE_DELAY = 1.0  # seconds

# Topic rules, ported from components/mpubsub/__init__.py:226-241 so both
# sides accept and reject exactly the same strings.
MAX_TOPIC_BYTES = 200

# MQTT wildcards. mpubsub topics may legally *contain* these characters (the
# ESPHome validator says so explicitly: "We do not enforce MQTT-style
# wildcards -- that's an application choice"), but this integration refuses
# them anyway: a caller writing against the mqtt API means a wildcard, and
# the wire carries only a topic CRC32, so wildcard matching is impossible.
# Treating "home/+/temp" as a literal that silently never matches would be
# strictly worse than an error. See docs/HOMEASSISTANT.md.
WILDCARD_CHARS = ("+", "#")

__all__ = ["DEFAULT_PORT", "DOMAIN", "PLATFORMS", "SCOPES"]
