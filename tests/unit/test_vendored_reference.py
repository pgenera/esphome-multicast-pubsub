"""Two consumers vendor a copy of reference.py; this is the drift gate.

Neither can import ``tests/unit/reference.py`` directly:

* ``custom_components/mpubsub/reference.py`` -- a Home Assistant custom
  component is copied to ``<config>/custom_components/`` on its own, with
  none of this repo around it.
* ``python/mpubsub/wire.py`` -- the installable ``mpubsub`` library ships as
  a standalone package (pip-installable, used by e.g. SenseLink).

Each copy is a *copy*, never a fork. Vendoring verbatim is what keeps them
transport-and-API layers over the existing reference rather than further wire
implementations to keep in lockstep by hand: if the bytes are identical, the
framing cannot drift, and only the plumbing around it can (which the
respective host cross-checks cover against a real ESPHome binary).

Byte equality is asserted rather than, say, matching AST or exported names,
precisely so the fix is always the same single ``cp``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CANONICAL = REPO / "tests" / "unit" / "reference.py"

# (vendored copy, the cp that re-syncs it)
_COPIES = [
    (
        REPO / "custom_components" / "mpubsub" / "reference.py",
        "cp tests/unit/reference.py custom_components/mpubsub/reference.py",
    ),
    (
        REPO / "python" / "mpubsub" / "wire.py",
        "cp tests/unit/reference.py python/mpubsub/wire.py",
    ),
]


@pytest.mark.parametrize("vendored,sync_cmd", _COPIES, ids=lambda v: str(v))
def test_vendored_copy_exists(vendored: Path, sync_cmd: str) -> None:
    assert vendored.exists(), (
        f"{vendored.relative_to(REPO)} is missing. It cannot import "
        f"tests/unit/reference.py, so it needs its own copy:\n    {sync_cmd}"
    )


@pytest.mark.parametrize("vendored,sync_cmd", _COPIES, ids=lambda v: str(v))
def test_vendored_reference_is_byte_identical(vendored: Path, sync_cmd: str) -> None:
    assert vendored.read_bytes() == CANONICAL.read_bytes(), (
        f"{vendored.relative_to(REPO)} has drifted from "
        f"{CANONICAL.relative_to(REPO)}.\n\n"
        f"The vendored copy is a copy, never an edit target -- edit "
        f"{CANONICAL.relative_to(REPO)} (it is the source of truth the C++ "
        f"and Go implementations are checked against), then re-sync:\n"
        f"    {sync_cmd}"
    )
