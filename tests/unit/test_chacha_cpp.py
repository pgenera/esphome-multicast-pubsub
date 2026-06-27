"""Runs the vendored C++ ChaCha20-Poly1305 self-check (RFC 8439 vectors +
roundtrip + tamper detection). Build with ``make chacha_test`` first."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).parent


@pytest.mark.parametrize("binary", ["chacha_test", "chacha_test_san"])
def test_cpp_chacha_self_check(binary: str) -> None:
    path = HERE / binary
    if not path.exists():
        pytest.skip(f"{path} not built; run `make {binary}` first")
    proc = subprocess.run([str(path)], capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ALL OK" in proc.stdout, proc.stdout
