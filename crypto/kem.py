"""ML-KEM (FIPS 203) session-key establishment, via oqs-python / liboqs.

Runs inside the Dockerized server (see SETUP.md - native liboqs builds
reliably fail on Windows without a cmake/ninja/C-toolchain). This module is
the reference implementation named in the spec; if `import oqs` fails here,
that is a setup problem to fix per SETUP.md, not a reason to substitute a
different crypto library.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# `oqs` is imported lazily inside each function/class below, rather than at
# module level, so that this module (and anything that merely imports pure
# helpers like `derive_channel_key`) can be imported even where liboqs isn't
# installed - e.g. native Windows without the Docker fallback (SETUP.md).
# The actual KEM operations still always use the real oqs/liboqs; nothing is
# substituted or mocked.

DEFAULT_KEM_ALG = os.getenv("KEM_ALG", "ML-KEM-768")

SUPPORTED_KEM_ALGS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}

CHANNEL_KEY_LEN = 32  # AES-256-GCM key length
_HKDF_INFO = b"pq-biometric-auth channel key v1"


def _check_alg(alg: str) -> None:
    if alg not in SUPPORTED_KEM_ALGS:
        raise ValueError(f"Unsupported KEM alg {alg!r}; expected one of {sorted(SUPPORTED_KEM_ALGS)}")


class ServerKemSession:
    """Server side of one ML-KEM exchange: generate a keypair, publish the
    public key, later decapsulate a ciphertext the client sends back.

    Holds the native secret key for the lifetime of the session, so must be
    explicitly closed (or used as a context manager) once the session ends.
    """

    def __init__(self, alg: str = DEFAULT_KEM_ALG):
        import oqs

        _check_alg(alg)
        self.alg = alg
        self._kem = oqs.KeyEncapsulation(alg)
        self.public_key: bytes | None = None
        self.shared_secret: bytes | None = None

    def generate_keypair(self) -> bytes:
        self.public_key = self._kem.generate_keypair()
        return self.public_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        self.shared_secret = self._kem.decap_secret(ciphertext)
        return self.shared_secret

    def close(self) -> None:
        self._kem.free()

    def __enter__(self) -> "ServerKemSession":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def client_encapsulate(server_public_key: bytes, alg: str = DEFAULT_KEM_ALG) -> tuple[bytes, bytes]:
    """One-shot client operation: encapsulate against the server's public
    key, returning (ciphertext_to_send_to_server, shared_secret)."""
    import oqs

    _check_alg(alg)
    with oqs.KeyEncapsulation(alg) as client_kem:
        ciphertext, shared_secret = client_kem.encap_secret(server_public_key)
    return ciphertext, shared_secret


def derive_channel_key(shared_secret: bytes, salt: bytes | None = None) -> bytes:
    """HKDF-SHA256 the raw ML-KEM shared secret into an AES-256-GCM key,
    with domain separation from any other use of the same shared secret."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=CHANNEL_KEY_LEN, salt=salt, info=_HKDF_INFO)
    return hkdf.derive(shared_secret)


def kem_details(alg: str = DEFAULT_KEM_ALG) -> dict:
    """Algorithm metadata (key/ciphertext sizes etc.) - used by the
    evaluation harness for the PQC-vs-classical payload-size comparison."""
    import oqs

    _check_alg(alg)
    with oqs.KeyEncapsulation(alg) as kem:
        return dict(kem.details)
