"""AES-256-GCM payload sealing over an ML-KEM shared secret (spec Section 5.2:
"shared_secret is then used as an AES-256-GCM key for the actual
video/data channel").

The channel key is k = HKDF-SHA256(K, salt=session_nonce) (crypto/kem.py),
so it is bound to one session, and the session_id is authenticated as GCM
associated data so a payload sealed for one session cannot be submitted
under another. Shared by the client (sealing) and server (opening) so both
sides derive and use the key identically.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.kem import derive_channel_key

AEAD_NONCE_LEN = 12  # 96-bit GCM nonce


def seal_payload(shared_secret: bytes, session_nonce: bytes, session_id: str, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt `plaintext`, returning (aead_nonce, ciphertext_with_tag)."""
    key = derive_channel_key(shared_secret, salt=session_nonce)
    aead_nonce = os.urandom(AEAD_NONCE_LEN)
    return aead_nonce, AESGCM(key).encrypt(aead_nonce, plaintext, session_id.encode("utf-8"))


def open_payload(shared_secret: bytes, session_nonce: bytes, session_id: str, aead_nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate; raises cryptography.exceptions.InvalidTag
    on any tampering or session mismatch."""
    key = derive_channel_key(shared_secret, salt=session_nonce)
    return AESGCM(key).decrypt(aead_nonce, ciphertext, session_id.encode("utf-8"))


def evidence_hash_of(frame_bytes: list[bytes]) -> bytes:
    """Canonical evidence hash: SHA-256 over the encoded bytes of every
    submitted frame, in order - exactly the bytes the server receives, so it
    can recompute and compare without re-encoding anything. Each frame is
    length-prefixed so frame boundaries are part of what is signed."""
    h = hashlib.sha256()
    for chunk in frame_bytes:
        h.update(len(chunk).to_bytes(8, "big"))
        h.update(chunk)
    return h.digest()
