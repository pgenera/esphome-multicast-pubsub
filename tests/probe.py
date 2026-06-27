#!/usr/bin/env python3
"""Standalone probe / publisher for the mpubsub protocol.

Examples:
    # Listen for raw publications, render as utf-8 if possible:
    python3 probe.py --topic test/temp

    # Listen for typed publications, render fields by tag/wire type:
    python3 probe.py --topic test/climate

    # Same, but with a schema -- decoded fields show declared names:
    python3 probe.py --topic test/climate --schema my-device.yaml

    # Publish a raw text payload:
    python3 probe.py --topic test/temp --publish 42.5

    # Publish a typed protobuf message using a schema:
    python3 probe.py --topic test/climate --schema my-device.yaml \\
        --message room_climate \\
        --field temperature=22.5 --field humidity=50 --field room_id=garage

probe.py uses only the Python standard library plus the reference
implementations in ``tests/unit/`` (and ``PyYAML`` when ``--schema`` is
passed). It is the third independent implementation of the wire
protocol after the C++ component and the codegen-emitted typed
encoders, so seeing this script decode a packet correctly is strong
evidence the C++ encoder and the typed decoder agree byte-for-byte.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "unit"))
sys.path.insert(0, str(HERE.parent / "components" / "mpubsub"))

from reference import (  # noqa: E402
    DEFAULT_PORT,
    ENCODING_PROTOBUF,
    ENCODING_RAW,
    SCOPE_LINK_LOCAL,
    SCOPE_ORG_LOCAL,
    SCOPE_SITE_LOCAL,
    WireError,
    decode as decode_envelope,
    encode as encode_envelope,
    topic_to_group,
)
import protobuf as pb  # noqa: E402  -- tests/unit/protobuf.py


_ENCODING_NAMES = {ENCODING_RAW: "RAW", ENCODING_PROTOBUF: "PROTOBUF"}

SCOPES = {
    "link-local": SCOPE_LINK_LOCAL,
    "site-local": SCOPE_SITE_LOCAL,
    "organization-local": SCOPE_ORG_LOCAL,
}


# ---------------------------------------------------------------------------
# Schema loading (optional, only when --schema is passed)
# ---------------------------------------------------------------------------


def _load_schemas(path: Path) -> dict[int, dict]:
    """Read a YAML file's ``mpubsub.messages:`` block and return
    a mapping from SCHEMA_ID to a dict of ``{id, fields: [{name,type,tag,repeated}]}``.

    ESPHome configs use custom YAML tags (``!lambda``, ``!secret``,
    ``!include``) that PyYAML's safe loader doesn't know about. Register
    loose constructors that coerce them to opaque strings -- we never
    inspect those values, we only need the messages: section.
    """
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as e:
        raise SystemExit(
            "probe.py needs PyYAML for --schema; install via `pip install pyyaml`"
        ) from e

    class _TolerantLoader(yaml.SafeLoader):
        pass

    def _ignore_tag(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    # Match every custom ESPHome tag (and anything else unknown).
    _TolerantLoader.add_multi_constructor("!", _ignore_tag)
    _TolerantLoader.add_multi_constructor("tag:", _ignore_tag)

    raw = yaml.load(path.read_text(), Loader=_TolerantLoader)
    if not isinstance(raw, dict):
        raise SystemExit(f"{path}: top level is not a YAML mapping")
    section = raw.get("mpubsub", {})
    messages = section.get("messages", []) if isinstance(section, dict) else []
    if not messages:
        raise SystemExit(f"{path}: no `mpubsub.messages:` block found")

    # Defer to the actual codegen module for SCHEMA_ID so we stay in sync.
    from proto_emitter import Field as PField, Message as PMessage, schema_id

    out: dict[int, dict] = {}
    for entry in messages:
        fields = []
        for f in entry.get("fields", []):
            fields.append(
                PField(
                    name=f["name"],
                    type=f["type"],
                    tag=int(f["tag"]),
                    repeated=bool(f.get("repeated", False)),
                )
            )
        msg = PMessage(id=entry["id"], fields=tuple(fields))
        out[schema_id(msg)] = {
            "id": entry["id"],
            "fields": [
                {"name": f.name, "type": f.type, "tag": f.tag, "repeated": f.repeated}
                for f in fields
            ],
        }
    return out


# ---------------------------------------------------------------------------
# Rendering an incoming packet
# ---------------------------------------------------------------------------


def _render_protobuf(
    body: bytes, schemas: dict[int, dict] | None
) -> str:
    """Decode a PROTOBUF body. First two bytes are SCHEMA_ID (LE)."""
    if len(body) < 2:
        return f"[malformed: body too short for SCHEMA_ID ({len(body)} B)]"
    schema_id = body[0] | (body[1] << 8)
    proto_bytes = body[2:]

    try:
        fields = pb.decode(proto_bytes)
    except ValueError as e:
        return f"schema_id={schema_id:04x} [protobuf parse error: {e}]"

    schema = schemas.get(schema_id) if schemas else None
    if schema is None:
        # Schemaless dump: tag/wire/raw
        parts = []
        for f in fields:
            if f.wire == pb.WIRE_VARINT:
                v = f.raw
                parts.append(f"#{f.tag}=varint:{v}")
            elif f.wire == pb.WIRE_LENGTH:
                raw = f.raw
                # Best-effort: render printable UTF-8, else hex.
                try:
                    s = raw.decode("utf-8")
                    if s.isprintable():
                        parts.append(f"#{f.tag}=str:{s!r}")
                    else:
                        parts.append(f"#{f.tag}=bytes:{raw.hex()}")
                except UnicodeDecodeError:
                    parts.append(f"#{f.tag}=bytes:{raw.hex()}")
            elif f.wire == pb.WIRE_FIXED32:
                fl = struct.unpack("<f", struct.pack("<I", f.raw))[0]
                parts.append(f"#{f.tag}=fixed32:{fl}")
        return f"schema_id={schema_id:04x} (schemaless) " + " ".join(parts)

    # Schema-aware rendering: build {tag → (name, type, repeated)} map and
    # group repeated fields together into a list.
    tag_meta = {f["tag"]: f for f in schema["fields"]}
    by_name: dict[str, object] = {}
    repeated_names: set[str] = {f["name"] for f in schema["fields"] if f["repeated"]}
    for f in fields:
        meta = tag_meta.get(f.tag)
        if meta is None:
            by_name[f"<tag {f.tag}>"] = _coerce_field(f, "unknown")
            continue
        value = _coerce_field(f, meta["type"])
        if meta["repeated"]:
            by_name.setdefault(meta["name"], []).append(value)  # type: ignore[union-attr]
        else:
            by_name[meta["name"]] = value
    # Ensure repeated fields that received zero values still render as []
    for name in repeated_names:
        by_name.setdefault(name, [])

    return f"{schema['id']}(schema_id={schema_id:04x}) " + json.dumps(by_name, default=str)


def _coerce_field(f: pb.Field, type_name: str) -> object:
    """Convert a parsed protobuf Field into the YAML-declared type."""
    if f.wire == pb.WIRE_VARINT:
        v = f.raw
        if type_name == "bool":
            return bool(v)
        if type_name == "sint32":
            return pb.decode_zigzag32(v & 0xFFFFFFFF)
        if type_name == "sint64":
            return pb.decode_zigzag64(v & 0xFFFFFFFFFFFFFFFF)
        if type_name in ("int32", "int64"):
            # Reinterpret as signed if the high bit is set (matches proto encoder).
            if type_name == "int32" and v >> 32:
                return struct.unpack("<q", struct.pack("<Q", v))[0]
            return struct.unpack("<q", struct.pack("<Q", v))[0] if v >> 63 else v
        return v  # uint32/uint64 unchanged
    if f.wire == pb.WIRE_FIXED32:
        if type_name == "float":
            return struct.unpack("<f", struct.pack("<I", f.raw))[0]
        return f.raw
    if f.wire == pb.WIRE_LENGTH:
        raw = f.raw
        if type_name == "string":
            return raw.decode("utf-8", errors="replace")
        if type_name == "bytes":
            return raw.hex()
        return raw.hex()
    return None


# ---------------------------------------------------------------------------
# Publish-side: build a protobuf body from --field args
# ---------------------------------------------------------------------------


def _build_typed_payload(schema: dict, fields: list[str]) -> tuple[bytes, int]:
    """Build a protobuf body from CLI ``--field name=value`` arguments.

    Returns ``(body, schema_id)`` where body is just the protobuf bytes
    (the 2-byte schema id is prepended by the caller). ``fields`` is a list
    of ``"name=value"`` strings; repeated fields may be specified multiple
    times.
    """
    from proto_emitter import Field as PField, Message as PMessage, schema_id

    name_to_meta = {f["name"]: f for f in schema["fields"]}

    # Accumulate values per field name (lists for repeated fields).
    values: dict[str, list[str]] = {}
    for spec in fields:
        if "=" not in spec:
            raise SystemExit(f"--field expects NAME=VALUE, got {spec!r}")
        name, _, val = spec.partition("=")
        if name not in name_to_meta:
            raise SystemExit(
                f"unknown field {name!r}; declared: {sorted(name_to_meta)}"
            )
        values.setdefault(name, []).append(val)

    body = b""
    for meta in schema["fields"]:
        vs = values.get(meta["name"], [])
        if not meta["repeated"] and len(vs) > 1:
            raise SystemExit(
                f"--field {meta['name']!r} given {len(vs)} times but isn't repeated"
            )
        for raw in vs:
            body += _encode_one(meta["tag"], meta["type"], raw)

    # Compute schema id from the schema dict so probe.py agrees with the codegen.
    msg = PMessage(
        id=schema["id"],
        fields=tuple(
            PField(name=f["name"], type=f["type"], tag=f["tag"], repeated=f["repeated"])
            for f in schema["fields"]
        ),
    )
    return body, schema_id(msg)


def _encode_one(tag: int, type_name: str, raw: str) -> bytes:
    if type_name == "bool":
        return pb.encode_bool(tag, raw.lower() in ("1", "true", "yes"))
    if type_name == "int32":
        return pb.encode_int32(tag, int(raw))
    if type_name == "int64":
        return pb.encode_int64(tag, int(raw))
    if type_name == "uint32":
        return pb.encode_uint32(tag, int(raw))
    if type_name == "uint64":
        return pb.encode_uint64(tag, int(raw))
    if type_name == "sint32":
        return pb.encode_sint32(tag, int(raw))
    if type_name == "sint64":
        return pb.encode_sint64(tag, int(raw))
    if type_name == "float":
        return pb.encode_float(tag, float(raw))
    if type_name == "string":
        return pb.encode_string(tag, raw)
    if type_name == "bytes":
        return pb.encode_bytes(tag, bytes.fromhex(raw))
    raise SystemExit(f"unsupported type {type_name!r}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--topic", required=True)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument(
        "--scope", choices=sorted(SCOPES), default="link-local",
        help="IPv6 multicast scope nibble (default: link-local for loopback)",
    )
    p.add_argument(
        "--schema", metavar="YAML", type=Path,
        help="YAML file containing a mpubsub.messages: block. "
             "When set, incoming PROTOBUF packets are decoded with field names "
             "from the matching schema; typed publishes need this flag.",
    )
    p.add_argument(
        "--publish", metavar="TEXT", nargs="?", const="",
        help="If given without --message, publish TEXT as a raw payload. "
             "With --message + --field, publish a typed protobuf message.",
    )
    p.add_argument(
        "--message", metavar="ID",
        help="With --publish: the messages: id to publish as. Requires --schema.",
    )
    p.add_argument(
        "--field", metavar="NAME=VALUE", action="append", default=[],
        help="Set a typed-message field. Repeat for repeated fields.",
    )
    p.add_argument(
        "--iface", default=None,
        help="Interface name or index for IPv6 multicast (default: system).",
    )
    p.add_argument(
        "--timeout", type=float, default=None,
        help="Stop listening after N seconds. Default: run forever.",
    )
    p.add_argument(
        "--max-packets", type=int, default=None,
        help="Stop listening after N successfully-decoded packets.",
    )
    args = p.parse_args()

    scope = SCOPES[args.scope]
    group = topic_to_group(args.topic, scope)
    print(f"# topic={args.topic!r} -> group=[{group}]:{args.port}", file=sys.stderr)

    schemas = _load_schemas(args.schema) if args.schema is not None else None

    if args.publish is not None:
        return _do_publish(args, group, schemas)

    return _do_listen(args, group, schemas)


def _do_publish(args, group, schemas) -> int:
    if args.message:
        if not schemas:
            raise SystemExit("--message requires --schema")
        target = next((s for s in schemas.values() if s["id"] == args.message), None)
        if target is None:
            raise SystemExit(
                f"message {args.message!r} not in --schema; declared: "
                f"{sorted(s['id'] for s in schemas.values())}"
            )
        body, sid = _build_typed_payload(target, args.field)
        wire = encode_envelope(
            args.topic, bytes([sid & 0xFF, (sid >> 8) & 0xFF]) + body,
            encoding=ENCODING_PROTOBUF,
        )
        kind = f"typed {args.message} (schema_id={sid:04x})"
    else:
        payload = (args.publish or "").encode("utf-8")
        wire = encode_envelope(args.topic, payload, encoding=ENCODING_RAW)
        kind = "raw"

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    if args.iface is not None:
        idx = socket.if_nametoindex(args.iface) if not args.iface.isdigit() else int(args.iface)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    sock.sendto(wire, (str(group), args.port))
    print(f"sent {len(wire)} bytes ({kind})")
    return 0


def _do_listen(args, group, schemas) -> int:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("::", args.port))
    idx = 0
    if args.iface is not None:
        idx = socket.if_nametoindex(args.iface) if not args.iface.isdigit() else int(args.iface)
    mreq = group.packed + struct.pack("@I", idx)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    if args.timeout is not None:
        sock.settimeout(args.timeout)

    print(f"listening on [::]:{args.port} for group {group}...", file=sys.stderr)
    start = time.monotonic()
    count = 0
    while True:
        try:
            data, peer = sock.recvfrom(2048)
        except socket.timeout:
            return 0
        try:
            crc, encoding, payload, *_ = decode_envelope(data)
        except WireError as e:
            print(f"[bad packet from {peer}]: {e}")
            continue
        enc_name = _ENCODING_NAMES.get(encoding, f"0x{encoding:02x}")
        if encoding == ENCODING_RAW:
            try:
                decoded = f" {payload.decode('utf-8')!r}"
            except UnicodeDecodeError:
                decoded = ""
            print(
                f"+{time.monotonic() - start:.3f}s from {peer}: "
                f"crc={crc:08x} enc={enc_name} payload({len(payload)} B)={payload.hex()}{decoded}"
            )
        elif encoding == ENCODING_PROTOBUF:
            rendered = _render_protobuf(payload, schemas)
            print(
                f"+{time.monotonic() - start:.3f}s from {peer}: "
                f"crc={crc:08x} enc={enc_name} {rendered}"
            )
        else:
            print(
                f"+{time.monotonic() - start:.3f}s from {peer}: "
                f"crc={crc:08x} enc={enc_name} payload({len(payload)} B)={payload.hex()}"
            )
        count += 1
        if args.max_packets is not None and count >= args.max_packets:
            return 0


if __name__ == "__main__":
    sys.exit(main())
