"""The Home Assistant component vendors reference.py; this is the drift gate.

``custom_components/mpubsub/`` cannot import from ``tests/`` -- a HA custom
component is copied to ``<config>/custom_components/`` on its own, with none
of this repo around it -- so it ships its own copy of the wire reference.

That copy is a *copy*, never a fork. Vendoring it verbatim is what keeps the
component a transport-and-API layer over the existing reference rather than a
fourth wire implementation to keep in lockstep by hand: if the bytes are
identical, the framing cannot drift, and only the plumbing around it can
(which tests/ha/test_host_cross_check.py covers against a real ESPHome
binary).

Byte equality is asserted rather than, say, matching AST or exported names,
precisely so the fix is always the same single ``cp``.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANONICAL = REPO / "tests" / "unit" / "reference.py"
VENDORED = REPO / "custom_components" / "mpubsub" / "reference.py"

_SYNC_CMD = "cp tests/unit/reference.py custom_components/mpubsub/reference.py"


def test_vendored_copy_exists() -> None:
    assert VENDORED.exists(), (
        f"{VENDORED.relative_to(REPO)} is missing. The Home Assistant "
        f"component cannot import from tests/, so it needs its own copy:\n"
        f"    {_SYNC_CMD}"
    )


def test_vendored_reference_is_byte_identical() -> None:
    assert VENDORED.read_bytes() == CANONICAL.read_bytes(), (
        f"{VENDORED.relative_to(REPO)} has drifted from "
        f"{CANONICAL.relative_to(REPO)}.\n\n"
        f"The vendored copy is a copy, never an edit target -- edit "
        f"{CANONICAL.relative_to(REPO)} (it is the source of truth the C++ "
        f"and Go implementations are checked against), then re-sync:\n"
        f"    {_SYNC_CMD}"
    )
