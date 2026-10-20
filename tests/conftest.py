"""Shared test fixtures/markers.

`oqs` (liboqs-python) needs a working native liboqs build, which reliably
fails on native Windows without cmake/ninja/a C toolchain (see docs/SETUP.md).
Rather than importing at collection time and hard-failing the whole test
session outside Docker, we probe once here and expose `HAS_OQS` so
PQC-dependent test modules can `pytestmark = skip_if_no_oqs`. This is a test
convenience only - crypto/kem.py and crypto/signature.py always use the real
liboqs, never a substitute, per spec Section 11.
"""
from __future__ import annotations

import pytest

try:
    import oqs  # noqa: F401

    HAS_OQS = True
    _OQS_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - environment dependent
    HAS_OQS = False
    _OQS_IMPORT_ERROR = exc

skip_if_no_oqs = pytest.mark.skipif(
    not HAS_OQS,
    reason=(
        "liboqs native library unavailable in this environment "
        f"({_OQS_IMPORT_ERROR!r}). Run inside Docker per docs/SETUP.md, or "
        "install a native build toolchain (cmake/ninja/VS Build Tools)."
    ),
)
