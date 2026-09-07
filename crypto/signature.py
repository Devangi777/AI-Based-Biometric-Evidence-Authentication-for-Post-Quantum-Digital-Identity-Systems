"""ML-DSA (FIPS 204) signing/verification, via oqs-python / liboqs.

Used to sign the transaction-binding payload described in spec Section 7:
    binding_payload = evidence_hash || session_nonce || timestamp || challenge_response

See README.md "Assumptions" #2: in this prototype both the "client" signer
and the "server" verifier run inside the same Dockerized process (the
Streamlit demo has no native liboqs build available), so `SignerIdentity` is
deliberately generic about who calls it.
"""
from __future__ import annotations

import os

# `oqs` is imported lazily inside each function/class below (not at module
# level) so this module - and pure helpers like `build_binding_payload` - can
# be imported where liboqs isn't installed (see crypto/kem.py for the same
# rationale). The real oqs/liboqs is still always what performs signing.

DEFAULT_SIG_ALG = os.getenv("SIG_ALG", "ML-DSA-65")

SUPPORTED_SIG_ALGS = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}


def _check_alg(alg: str) -> None:
    if alg not in SUPPORTED_SIG_ALGS:
        raise ValueError(f"Unsupported signature alg {alg!r}; expected one of {sorted(SUPPORTED_SIG_ALGS)}")


class SignerIdentity:
    """Holds one party's ML-DSA signing keypair for the lifetime of a
    session. Must be closed (or used as a context manager) when done."""

    def __init__(self, alg: str = DEFAULT_SIG_ALG):
        import oqs

        _check_alg(alg)
        self.alg = alg
        self._sig = oqs.Signature(alg)
        self.public_key: bytes = self._sig.generate_keypair()

    def sign(self, message: bytes) -> bytes:
        return self._sig.sign(message)

    def close(self) -> None:
        self._sig.free()

    def __enter__(self) -> "SignerIdentity":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def verify(message: bytes, signature: bytes, public_key: bytes, alg: str = DEFAULT_SIG_ALG) -> bool:
    import oqs

    _check_alg(alg)
    with oqs.Signature(alg) as verifier:
        return verifier.verify(message, signature, public_key)


def build_binding_payload(
    evidence_hash: bytes,
    session_id: str,
    timestamp: str,
    challenge_response: str = "",
) -> bytes:
    """Serialize the Section 7 binding payload:
    evidence_hash || session_nonce (session_id) || timestamp || challenge_response

    Note: Section 5.2's illustrative snippet omits challenge_response; Section
    7's full binding design (the mechanism actually implemented in
    binding/session_binding.py) includes it, so that is what this builds.
    """
    return evidence_hash + session_id.encode("utf-8") + timestamp.encode("utf-8") + challenge_response.encode("utf-8")


def sig_details(alg: str = DEFAULT_SIG_ALG) -> dict:
    """Algorithm metadata (key/signature sizes) - used by the evaluation
    harness for the PQC-vs-classical payload-size comparison."""
    import oqs

    _check_alg(alg)
    with oqs.Signature(alg) as sig:
        return dict(sig.details)
