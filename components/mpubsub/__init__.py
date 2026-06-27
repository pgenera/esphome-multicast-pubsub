"""ESPHome external component: brokerless IPv6 multicast publish/subscribe.

See ../../README.md for the protocol specification.
"""

import hashlib

from esphome import automation
import esphome.codegen as cg
from esphome.components import sensor as esphome_sensor
from esphome.components import time
import esphome.config_validation as cv
from esphome.components.api import CONF_ENCRYPTION
from esphome.const import (
    CONF_ACCURACY_DECIMALS,
    CONF_DISABLED_BY_DEFAULT,
    CONF_ENTITY_CATEGORY,
    CONF_ID,
    CONF_KEY,
    CONF_MQTT_ID,
    CONF_NAME,
    CONF_PAYLOAD,
    CONF_PORT,
    CONF_STATE_CLASS,
    CONF_TIME_ID,
    CONF_TOPIC,
    CONF_TRIGGER_ID,
    CONF_TYPE,
    ENTITY_CATEGORY_DIAGNOSTIC,
    STATE_CLASS_TOTAL_INCREASING,
)

from esphome import final_validate as fv
from esphome.core import CORE, ID

from . import proto_emitter

# Slot in CORE.data where we cache the declared `messages:` entries so the
# typed publish action's codegen (which runs after the component's to_code
# but doesn't have access to fv.full_config) can look up each schema's
# field shape.
_SCHEMA_REGISTRY_KEY = "multicast_pubsub_schemas"

CODEOWNERS = ["@pgenera"]
DEPENDENCIES = ["network"]
# We AUTO_LOAD `api` only when the user actually declares typed messages:
# in to_code below. Devices using only raw publish/subscribe don't pay the
# ~10KB cost of the API server. (A future upstream refactor splitting
# api/proto.{h,cpp} into a leaf `api_proto` sub-component would let us
# bring in only the protobuf primitives without the server runtime.)
AUTO_LOAD = ["socket", "sensor", "xxtea"]
MULTI_CONF = True

multicast_pubsub_ns = cg.esphome_ns.namespace("multicast_pubsub")
MulticastPubSub = multicast_pubsub_ns.class_("MulticastPubSub", cg.Component)
Scope = multicast_pubsub_ns.enum("Scope", is_class=True)
PublishAction = multicast_pubsub_ns.class_("PublishAction", automation.Action)
OnMessageTrigger = multicast_pubsub_ns.class_("OnMessageTrigger", automation.Trigger)

CONF_SCOPE = "scope"
CONF_HOPS = "hops"
CONF_RETRANSMIT_COUNT = "retransmit_count"
CONF_RETRANSMIT_DELAY = "retransmit_delay"
CONF_ON_MESSAGE = "on_message"
CONF_MESSAGES = "messages"
CONF_FIELDS = "fields"
CONF_TAG = "tag"
CONF_MESSAGE = "message"
CONF_REPEATED = "repeated"
CONF_VALUES = "values"
CONF_REQUIRE_ENCRYPTION = "require_encryption"
CONF_REPLAY_WINDOW = "replay_window"

SCOPES = {
    "link-local": Scope.LINK_LOCAL,
    "site-local": Scope.SITE_LOCAL,
    "organization-local": Scope.ORG_LOCAL,
}

# Mirrors components/mpubsub/wire_format.h. Hard cap.
# IPv6 minimum MTU (1280, RFC 8200 §5) minus IPv6 header (40) minus UDP
# header (8) = 1232 bytes deliverable on any IPv6 link without fragmentation.
MAX_DATAGRAM = 1232
HEADER_LEN = 12
MAX_PAYLOAD = MAX_DATAGRAM - HEADER_LEN  # 1220


def _static_payload_validator(value):
    """Reject configs whose payload is a static string > MAX_PAYLOAD.

    Templatable payloads (lambdas) are validated at runtime by the C++ side.
    """
    value = cv.string(value)
    encoded_len = len(value.encode("utf-8"))
    if encoded_len > MAX_PAYLOAD:
        raise cv.Invalid(
            f"payload is {encoded_len} bytes but the maximum publishable size "
            f"is {MAX_PAYLOAD} bytes (UDP datagram limit {MAX_DATAGRAM} minus "
            f"the {HEADER_LEN}-byte header)"
        )
    return value


def _message_id_validator(value):
    """Validate a typed-message id (used to reference the message from publish
    actions and on_message triggers).

    Restrict to identifier-like strings so the generated C++ type name is
    sane: alphanumeric + underscore/hyphen, starts with a letter.
    """
    value = cv.string_strict(value)
    if not value:
        raise cv.Invalid("message id must be non-empty")
    if not (value[0].isalpha() or value[0] == "_"):
        raise cv.Invalid(f"message id {value!r} must start with a letter or underscore")
    for c in value:
        if not (c.isalnum() or c in "_-"):
            raise cv.Invalid(
                f"message id {value!r}: invalid character {c!r} (allowed: alphanumeric, _, -)"
            )
    return value


def _field_name_validator(value):
    value = cv.string_strict(value)
    if not value:
        raise cv.Invalid("field name must be non-empty")
    if not (value[0].isalpha() or value[0] == "_"):
        raise cv.Invalid(f"field name {value!r} must start with a letter or underscore")
    for c in value:
        if not (c.isalnum() or c == "_"):
            raise cv.Invalid(
                f"field name {value!r}: invalid character {c!r} (allowed: alphanumeric, _)"
            )
    return value


def _field_type_validator(value):
    value = cv.string_strict(value)
    if value not in proto_emitter.VALID_TYPES:
        raise cv.Invalid(
            f"unknown field type {value!r}. Valid: {sorted(proto_emitter.VALID_TYPES)}"
        )
    return value


def _field_tag_validator(value):
    value = cv.positive_int(value)
    if not (1 <= value <= 536_870_911):
        raise cv.Invalid(f"field tag {value} out of range (1..536870911)")
    if 19000 <= value <= 19999:
        raise cv.Invalid(f"field tag {value} is in proto3's reserved range 19000..19999")
    return value


FIELD_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_NAME): _field_name_validator,
        cv.Required(CONF_TYPE): _field_type_validator,
        cv.Required(CONF_TAG): _field_tag_validator,
        cv.Optional(CONF_REPEATED, default=False): cv.boolean,
    }
)


def _message_validator(value):
    """Validate a single message declaration and raise the cv-friendly form
    of any proto_emitter errors."""
    schema = cv.Schema(
        {
            cv.Required(CONF_ID): _message_id_validator,
            cv.Required(CONF_FIELDS): cv.All(
                cv.ensure_list(FIELD_SCHEMA), cv.Length(min=1)
            ),
        }
    )
    value = schema(value)
    # Run the emitter's structural validation (duplicate tags etc) and
    # surface anything it complains about as a cv.Invalid.
    msg = proto_emitter.Message(
        id=value[CONF_ID],
        fields=tuple(
            proto_emitter.Field(
                name=f[CONF_NAME],
                type=f[CONF_TYPE],
                tag=f[CONF_TAG],
                repeated=f[CONF_REPEATED],
            )
            for f in value[CONF_FIELDS]
        ),
    )
    try:
        proto_emitter.validate(msg)
    except ValueError as e:
        raise cv.Invalid(str(e)) from e
    return value


def _messages_validator(value):
    """Validate the top-level messages: list and ensure ids are unique."""
    value = cv.ensure_list(_message_validator)(value)
    seen_ids = set()
    for msg in value:
        if msg[CONF_ID] in seen_ids:
            raise cv.Invalid(f"duplicate message id: {msg[CONF_ID]!r}")
        seen_ids.add(msg[CONF_ID])
    return value


def _retransmit_count_validator(value):
    """Accept 1..255 (finite) or -1 (indefinite). Reject 0 and anything else.

    Cross-field "delay >= 1s when count is -1" is enforced in
    FINAL_VALIDATE_SCHEMA where we can see both fields at once.
    """
    value = cv.int_(value)
    if value == -1:
        return value
    if value < 1 or value > 255:
        raise cv.Invalid(
            f"retransmit_count must be 1..255 or -1 (indefinite); got {value}"
        )
    return value


def _topic_validator(value):
    """Validate a pub/sub topic.

    Topics are arbitrary non-empty UTF-8 strings with no NUL bytes. We do not
    enforce MQTT-style wildcards or hierarchy — that's an application choice.
    """
    value = cv.string_strict(value)
    if "\x00" in value:
        raise cv.Invalid("topic must not contain NUL bytes")
    encoded = value.encode("utf-8")
    if len(encoded) == 0:
        raise cv.Invalid("topic must not be empty")
    if len(encoded) > 200:
        raise cv.Invalid(f"topic too long: {len(encoded)} bytes (limit 200)")
    return value


def _on_message_validator(config):
    """Top-level wire-up: each on_message: entry may opt into a typed
    schema by setting ``message: <schema_id>``. The trigger class used at
    codegen time is then the generated ``On<Pascal>Trigger`` rather than
    the raw byte-vector ``OnMessageTrigger``.

    The actual codegen happens in ``to_code`` once we know which message
    schemas exist; the schema id reference is resolved there.
    """
    # Wrap the underlying automation validator without re-declaring its
    # trigger id (the dynamic-class case rewrites the id type below).
    return automation.validate_automation(
        {
            cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(OnMessageTrigger),
            cv.Required(CONF_TOPIC): _topic_validator,
            cv.Optional(CONF_MESSAGE): _message_id_validator,
            cv.Optional(CONF_REQUIRE_ENCRYPTION, default=False): cv.boolean,
        }
    )(config)


CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(MulticastPubSub),
        cv.Optional(CONF_PORT, default=18512): cv.port,
        cv.Optional(CONF_SCOPE, default="link-local"): cv.enum(SCOPES, lower=True),
        cv.Optional(CONF_HOPS, default=1): cv.int_range(min=1, max=255),
        cv.Optional(CONF_RETRANSMIT_COUNT, default=1): _retransmit_count_validator,
        cv.Optional(CONF_RETRANSMIT_DELAY, default="100ms"): cv.positive_time_period_milliseconds,
        # Optional XXTEA-256 payload encryption. The user-supplied key string
        # is SHA-256'd to 32 bytes at codegen time -- same convention as
        # packet_transport's `encryption.key`.
        cv.Optional(CONF_ENCRYPTION): cv.Schema(
            {
                cv.Required(CONF_KEY): cv.string_strict,
                # Replay protection (Option B): stamp each encrypted publish
                # with the wall clock + a random nonce and drop stale /
                # duplicate packets within this freshness window on receive.
                # Requires a `time:` source (time_id). Omit to leave it off.
                cv.Optional(CONF_REPLAY_WINDOW): cv.positive_time_period_seconds,
                cv.Optional(CONF_TIME_ID): cv.use_id(time.RealTimeClock),
            }
        ),
        cv.Optional(CONF_MESSAGES, default=list): _messages_validator,
        cv.Optional(CONF_ON_MESSAGE): _on_message_validator,
    }
).extend(cv.COMPONENT_SCHEMA)


def _final_validate(config):
    """Two checks that can only run after all schemas have evaluated:

    1. If `messages:` is declared, `api:` must be present (we depend on
       its protobuf primitives in components/api/proto.h).
    2. If any `on_message: + message:` references a schema id, that
       schema must actually be declared in `messages:`.
    """
    if config.get(CONF_MESSAGES):
        full = fv.full_config.get()
        if "api" not in full:
            raise cv.Invalid(
                "mpubsub `messages:` requires the `api:` component to "
                "be configured (used for protobuf encoding primitives). Add an "
                "`api:` section to your YAML, or remove the `messages:` block "
                "to stick to raw payloads.",
                path=[CONF_MESSAGES],
            )

    # Indefinite retransmit needs a non-trivial spacing so the device
    # doesn't saturate the link. We pick 1s as the minimum -- shorter
    # intervals are almost certainly a misconfiguration.
    if config.get(CONF_RETRANSMIT_COUNT) == -1:
        delay = config.get(CONF_RETRANSMIT_DELAY)
        if delay is not None and delay.total_milliseconds < 1000:
            raise cv.Invalid(
                "retransmit_count: -1 (indefinite) requires "
                "retransmit_delay >= 1s",
                path=[CONF_RETRANSMIT_DELAY],
            )

    declared = {m[CONF_ID] for m in config.get(CONF_MESSAGES, [])}
    for i, trig in enumerate(config.get(CONF_ON_MESSAGE, [])):
        ref = trig.get(CONF_MESSAGE)
        if ref is None:
            continue
        if ref not in declared:
            raise cv.Invalid(
                f"on_message references unknown message {ref!r}; declare it "
                f"under `messages:`. Known: {sorted(declared) or '(none)'}",
                path=[CONF_ON_MESSAGE, i, CONF_MESSAGE],
            )

    # Replay protection needs a clock to measure freshness against: a
    # replay_window without a time_id has nothing to check the timestamp
    # against, so the receiver would fail closed and drop every packet.
    enc = config.get(CONF_ENCRYPTION)
    if enc and CONF_REPLAY_WINDOW in enc and CONF_TIME_ID not in enc:
        raise cv.Invalid(
            "encryption `replay_window` requires `time_id:` pointing at a "
            "`time:` component (the receiver measures packet freshness "
            "against the wall clock; without it every encrypted packet "
            "would be dropped).",
            path=[CONF_ENCRYPTION, CONF_REPLAY_WINDOW],
        )

    # require_encryption on any subscription requires the parent mpubsub:
    # block to have configured an encryption key -- otherwise the receiver
    # has no key to decrypt with and the marked topic would deliver nothing.
    if CONF_ENCRYPTION not in config:
        for i, trig in enumerate(config.get(CONF_ON_MESSAGE, [])):
            if trig.get(CONF_REQUIRE_ENCRYPTION):
                raise cv.Invalid(
                    "on_message `require_encryption: true` needs an "
                    "`encryption: key:` block on the parent mpubsub: "
                    "component (otherwise the receiver has no key and "
                    "every packet for this topic would be dropped).",
                    path=[CONF_ON_MESSAGE, i, CONF_REQUIRE_ENCRYPTION],
                )
    return config


def _register_schema(msg_cfg: dict) -> None:
    """Stash a message schema in CORE.data so the typed publish action's
    codegen can look it up later. Idempotent -- last write wins, which is
    fine because messages: ids are unique per component instance and
    duplicates across instances would have to declare identical shapes
    to compute the same SCHEMA_ID anyway."""
    CORE.data.setdefault(_SCHEMA_REGISTRY_KEY, {})[msg_cfg[CONF_ID]] = msg_cfg


def _lookup_message_schema(msg_id: str) -> dict | None:
    """Return the messages: entry matching ``msg_id``, or None."""
    return CORE.data.get(_SCHEMA_REGISTRY_KEY, {}).get(msg_id)


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    # Typed messages reference esphome::api::ProtoEncode / ProtoDecodableMessage,
    # so pull in proto.h from the api component (presence enforced by
    # FINAL_VALIDATE_SCHEMA above). cg.add_global appends a ';' to whatever
    # we emit, which a preprocessor directive doesn't want; the safest trick
    # is to wrap it in a dummy statement that swallows the trailing token.
    if config.get(CONF_MESSAGES):
        cg.add_global(cg.RawExpression(
            '#include "esphome/components/api/proto.h"\n'
            'struct multicast_pubsub_force_proto_include_'
        ))
    for msg_cfg in config.get(CONF_MESSAGES, []):
        _register_schema(msg_cfg)
        msg = proto_emitter.Message(
            id=msg_cfg[CONF_ID],
            fields=tuple(
                proto_emitter.Field(
                    name=f[CONF_NAME],
                    type=f[CONF_TYPE],
                    tag=f[CONF_TAG],
                    repeated=f[CONF_REPEATED],
                )
                for f in msg_cfg[CONF_FIELDS]
            ),
        )
        cg.add_global(cg.RawExpression(proto_emitter.emit_struct(msg)))

    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_port(config[CONF_PORT]))
    cg.add(var.set_scope(config[CONF_SCOPE]))
    cg.add(var.set_hops(config[CONF_HOPS]))
    cg.add(var.set_retransmit_count(config[CONF_RETRANSMIT_COUNT]))
    cg.add(var.set_retransmit_delay_ms(config[CONF_RETRANSMIT_DELAY].total_milliseconds))

    if CONF_ENCRYPTION in config:
        enc = config[CONF_ENCRYPTION]
        # Mirror packet_transport's hash_encryption_key(): SHA-256 the user
        # passphrase to a deterministic 32-byte XXTEA-256 key.
        digest = list(hashlib.sha256(enc[CONF_KEY].encode()).digest())
        cg.add(var.set_encryption_key(digest))
        # Optional replay protection: wire up the freshness window and the
        # time source the receiver clocks freshness against. Presence of
        # time_id when replay_window is set is enforced in _final_validate.
        if CONF_REPLAY_WINDOW in enc:
            cg.add(var.set_replay_window(int(enc[CONF_REPLAY_WINDOW].total_seconds)))
            time_var = await cg.get_variable(enc[CONF_TIME_ID])
            cg.add(var.set_time(time_var))

    # Auto-create diagnostic sensors for messages sent / received. Picked
    # up automatically by anything that iterates registered sensors
    # (prometheus, web_server, the HA API, ...). entity_category:
    # diagnostic puts them in HA's "Diagnostic" section so they don't
    # clutter the main entity list, but we deliberately don't mark them
    # `internal: True` -- the prometheus component skips internal
    # entities by default, which would defeat the whole point.
    parent_slug = str(config[CONF_ID].id)
    for slug, setter in (
        ("packets_sent", "set_packets_sent_sensor"),
        ("packets_received", "set_packets_received_sensor"),
    ):
        s_id = ID(f"{parent_slug}_{slug}", is_declaration=True, type=esphome_sensor.Sensor)
        s_config = {
            CONF_ID: s_id,
            CONF_NAME: slug.replace("_", " "),
            CONF_ACCURACY_DECIMALS: 0,
            CONF_STATE_CLASS: STATE_CLASS_TOTAL_INCREASING,
            CONF_ENTITY_CATEGORY: ENTITY_CATEGORY_DIAGNOSTIC,
            # Counters are diagnostics for tracking link health; default
            # them off in HA so they don't clutter the UI for the common
            # case of "I just want my sensor reading". Users can re-enable
            # per-device when investigating loss / retransmit behavior.
            CONF_DISABLED_BY_DEFAULT: True,
        }
        # When `mqtt:` is in the global config the sensor schema would
        # auto-generate a CONF_MQTT_ID via cv.OnlyWith(..., "mqtt").
        # That auto-generation produces an empty id at codegen time
        # (the validation-phase scan that normally populates
        # CORE.component_ids has already run by the time we're here).
        # Construct the id ourselves AND add it to CORE.component_ids
        # so the downstream register_component(...) call inside
        # setup_sensor_core_ -> register_mqtt_component sees it as a
        # declared-but-not-yet-registered Component.
        if "mqtt" in CORE.loaded_integrations:
            from esphome.components import mqtt as _mqtt
            mqtt_id = ID(
                f"{parent_slug}_{slug}_mqtt",
                is_declaration=True,
                type=_mqtt.MQTTSensorComponent,
            )
            s_config[CONF_MQTT_ID] = mqtt_id
            CORE.component_ids.add(mqtt_id.id)
        s_config = esphome_sensor.sensor_schema(esphome_sensor.Sensor)(s_config)
        s_var = await esphome_sensor.new_sensor(s_config)
        cg.add(getattr(var, setter)(s_var))

    for conf in config.get(CONF_ON_MESSAGE, []):
        require_enc = conf.get(CONF_REQUIRE_ENCRYPTION, False)
        if CONF_MESSAGE in conf:
            # Typed receive: instantiate the generated On<Pascal>Trigger
            # class that subscribes via subscribe_typed<T> and emits the
            # decoded struct as the trigger argument.
            class_name = proto_emitter.pascal_case(conf[CONF_MESSAGE])
            trigger_cls = multicast_pubsub_ns.class_(
                f"On{class_name}Trigger", automation.Trigger
            )
            msg_struct = multicast_pubsub_ns.namespace("messages").class_(class_name)
            # Re-declare the trigger id with the typed class so cg.new_Pvariable
            # produces the right C++ type.
            trigger_id = conf[CONF_TRIGGER_ID]
            trigger_id.type = trigger_cls
            trigger = cg.new_Pvariable(trigger_id, var, conf[CONF_TOPIC], require_enc)
            # Trigger<T> hands the user lambda `T x` by value, matching the
            # `Trigger<MsgStruct>` base of the generated trigger class.
            await automation.build_automation(trigger, [(msg_struct, "x")], conf)
        else:
            # Raw receive: bytes vector argument, original behavior.
            trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID], var, conf[CONF_TOPIC], require_enc)
            await automation.build_automation(
                trigger, [(cg.std_vector.template(cg.uint8), "x")], conf
            )


def _publish_action_mode_validator(config: dict) -> dict:
    """Enforce that a mpubsub.publish action is either raw
    (`payload:` only) or typed (`message:` + `values:`), never both
    and never neither.
    """
    has_payload = CONF_PAYLOAD in config
    has_message = CONF_MESSAGE in config
    if has_payload and has_message:
        raise cv.Invalid(
            "mpubsub.publish: `payload:` and `message:` are mutually "
            "exclusive -- pick one. Use `payload:` for opaque bytes, or "
            "`message: + values:` for a typed protobuf message."
        )
    if not has_payload and not has_message:
        raise cv.Invalid(
            "mpubsub.publish requires either `payload:` (raw mode) "
            "or `message: + values:` (typed mode)."
        )
    if has_message and CONF_VALUES not in config:
        raise cv.Invalid(
            "mpubsub.publish with `message:` requires a `values:` "
            "mapping (use `values: {}` to publish a fully-default message)."
        )
    return config


PUBLISH_ACTION_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.use_id(MulticastPubSub),
            cv.Required(CONF_TOPIC): cv.templatable(_topic_validator),
            cv.Optional(CONF_PAYLOAD): cv.templatable(_static_payload_validator),
            cv.Optional(CONF_MESSAGE): _message_id_validator,
            # Per-call override of the component-level retransmit_count.
            # Same range as the component option (1..255 or -1 indefinite).
            # No cross-field delay check here -- runtime uses the
            # component's configured retransmit_delay either way.
            cv.Optional(CONF_RETRANSMIT_COUNT): cv.templatable(
                _retransmit_count_validator
            ),
            # Values are validated lazily -- per-field type-coercion happens
            # at codegen time when we know which message they belong to.
            cv.Optional(CONF_VALUES): cv.Schema({cv.string_strict: cv.valid}),
        }
    ),
    _publish_action_mode_validator,
)


def _publish_action_class(msg_id: str):
    """Return a MockObjClass for the codegen-emitted Publish<Msg>Action.

    The actual C++ class lives in the generated namespace (emitted by
    proto_emitter.emit_struct), so this is just a Python handle we hand
    to cg.declare_id / cg.new_Pvariable.
    """
    class_name = f"Publish{proto_emitter.pascal_case(msg_id)}Action"
    return multicast_pubsub_ns.class_(class_name, automation.Action)


@automation.register_action(
    "mpubsub.publish",
    PublishAction,
    PUBLISH_ACTION_SCHEMA,
    synchronous=True,
)
async def publish_action_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])

    if CONF_PAYLOAD in config:
        # Raw publish path (existing behavior).
        var = cg.new_Pvariable(action_id, template_arg, parent)
        topic_tpl = await cg.templatable(config[CONF_TOPIC], args, cg.std_string)
        cg.add(var.set_topic(topic_tpl))
        payload_tpl = await cg.templatable(
            config[CONF_PAYLOAD], args, cg.std_string
        )
        cg.add(var.set_payload(payload_tpl))
        if CONF_RETRANSMIT_COUNT in config:
            rc_tpl = await cg.templatable(
                config[CONF_RETRANSMIT_COUNT], args, cg.uint8
            )
            cg.add(var.set_retransmit_count(rc_tpl))
        return var

    # Typed publish path -- rewrite the action_id to point at the
    # codegen-emitted Publish<Msg>Action class (declared in main.cpp via
    # cg.add_global in to_code() above), then call its per-field
    # templatable setters.
    msg_id = config[CONF_MESSAGE]
    schema = _lookup_message_schema(msg_id)
    if schema is None:
        raise cv.Invalid(
            f"mpubsub.publish references unknown message {msg_id!r}. "
            f"Declare it under `mpubsub.messages:` or pick a "
            f"different message id.",
            path=[CONF_MESSAGE],
        )

    field_types = {
        f[CONF_NAME]: (f[CONF_TYPE], f[CONF_REPEATED]) for f in schema[CONF_FIELDS]
    }
    for field_name in config.get(CONF_VALUES, {}):
        if field_name not in field_types:
            raise cv.Invalid(
                f"unknown field {field_name!r} in `values:` for message "
                f"{msg_id!r}. Declared fields: {sorted(field_types)}",
                path=[CONF_VALUES, field_name],
            )

    action_cls = _publish_action_class(msg_id)
    action_id.type = action_cls
    var = cg.new_Pvariable(action_id, template_arg)
    cg.add(var.set_parent(parent))

    topic_tpl = await cg.templatable(config[CONF_TOPIC], args, cg.std_string)
    cg.add(var.set_topic(topic_tpl))

    if CONF_RETRANSMIT_COUNT in config:
        rc_tpl = await cg.templatable(
            config[CONF_RETRANSMIT_COUNT], args, cg.int16
        )
        cg.add(var.set_retransmit_count(rc_tpl))

    for field_name, raw_value in config.get(CONF_VALUES, {}).items():
        type_name, repeated = field_types[field_name]
        cpp_value_type = _cpp_value_type(type_name, repeated)
        tpl = await cg.templatable(raw_value, args, cpp_value_type)
        cg.add(getattr(var, f"set_{field_name}")(tpl))

    return var


def _cpp_value_type(type_name: str, repeated: bool):
    """Map a YAML field type to the C++ type used by the action's
    TEMPLATABLE_VALUE setter."""
    base_lookup = {
        "bool": cg.bool_,
        "int32": cg.int32,
        "int64": cg.int64,
        "uint32": cg.uint32,
        "uint64": cg.uint64,
        "sint32": cg.int32,
        "sint64": cg.int64,
        "float": cg.float_,
        "string": cg.std_string,
        "bytes": cg.std_vector.template(cg.uint8),
    }
    base = base_lookup[type_name]
    if repeated:
        return cg.std_vector.template(base)
    return base


