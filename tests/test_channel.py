"""crypto/channel.py: AES-256-GCM sealing over an ML-KEM shared secret, and
the canonical evidence hash. Pure `cryptography` - no liboqs needed, since a
random 32-byte value stands in for the KEM shared secret here (the real
ML-KEM path is covered end-to-end in tests/test_server.py)."""
from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from crypto.channel import evidence_hash_of, open_payload, seal_payload

SECRET, NONCE, SESSION = os.urandom(32), os.urandom(32), "session-a"


def test_round_trip():
    aead_nonce, ct = seal_payload(SECRET, NONCE, SESSION, b"payload")
    assert open_payload(SECRET, NONCE, SESSION, aead_nonce, ct) == b"payload"


@pytest.mark.parametrize(
    "secret,nonce,session",
    [(os.urandom(32), NONCE, SESSION), (SECRET, os.urandom(32), SESSION), (SECRET, NONCE, "session-b")],
    ids=["wrong-shared-secret", "wrong-session-nonce", "wrong-session-id"],
)
def test_mismatched_context_fails_authentication(secret, nonce, session):
    aead_nonce, ct = seal_payload(SECRET, NONCE, SESSION, b"payload")
    with pytest.raises(InvalidTag):
        open_payload(secret, nonce, session, aead_nonce, ct)


def test_tampered_ciphertext_fails_authentication():
    aead_nonce, ct = seal_payload(SECRET, NONCE, SESSION, b"payload")
    with pytest.raises(InvalidTag):
        open_payload(SECRET, NONCE, SESSION, aead_nonce, bytes([ct[0] ^ 1]) + ct[1:])


def test_evidence_hash_covers_frame_boundaries():
    assert evidence_hash_of([b"ab", b"c"]) != evidence_hash_of([b"a", b"bc"])
    assert evidence_hash_of([b"ab", b"c"]) == evidence_hash_of([b"ab", b"c"])
