"""HTTP client for the FastAPI server (server/main.py).

The client hashes the captured evidence itself (Section 3:
`evidence_hash = SHA-256(frame bytes)`). If liboqs is importable here it
also runs ML-KEM-768 encapsulation against the session's public key and
seals the verification payload with AES-256-GCM (/verify-sealed), so the
evidence never crosses the network in plaintext. Without liboqs (e.g. native
Windows, see SETUP.md) it falls back to the plaintext /verify endpoint.
ML-DSA signing is still delegated to the server's per-session "client
identity" (README.md "Assumptions" #2).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

import numpy as np
import requests

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
_TIMEOUT_SECONDS = 30


class ApiError(RuntimeError):
    pass


def _request(method: str, path: str, **kwargs) -> dict:
    url = f"{API_BASE_URL}{path}"
    try:
        resp = requests.request(method, url, timeout=_TIMEOUT_SECONDS, **kwargs)
    except requests.exceptions.RequestException as exc:
        raise ApiError(f"Could not reach server at {url}: {exc}") from exc
    if resp.status_code >= 400:
        raise ApiError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text}")
    return resp.json()


def health() -> dict:
    return _request("GET", "/health")


def session_start() -> dict:
    return _request("POST", "/session/start")


def establish_channel(session_id: str) -> dict:
    return _request("POST", f"/session/{session_id}/channel")


def sign_evidence(session_id: str, evidence_hash_hex: str, timestamp: str, challenge_response: str) -> dict:
    return _request(
        "POST",
        f"/session/{session_id}/evidence",
        json={
            "evidence_hash": evidence_hash_hex,
            "timestamp": timestamp,
            "challenge_response": challenge_response,
        },
    )


def verify_evidence(
    session_id: str,
    evidence_hash_hex: str,
    timestamp: str,
    challenge_response: str,
    signature_hex: str,
    frames_b64: list[str],
    frame_timestamps: list[float] | None = None,
) -> dict:
    return _request(
        "POST",
        f"/session/{session_id}/verify",
        json={
            "evidence_hash": evidence_hash_hex,
            "timestamp": timestamp,
            "challenge_response": challenge_response,
            "signature": signature_hex,
            "frames_b64": frames_b64,
            "frame_timestamps": frame_timestamps,
        },
    )


def end_session(session_id: str) -> dict:
    return _request("DELETE", f"/session/{session_id}")


def reset_replay_store() -> dict:
    """Demo rehearsal helper; the server only allows it with DEMO_MODE=true."""
    return _request("POST", "/demo/reset-replay-store")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso(offset_seconds: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def can_seal() -> bool:
    """True if this client can run ML-KEM itself (liboqs importable), and so
    can send the verification payload over the sealed post-quantum channel."""
    try:
        import oqs  # noqa: F401
    except Exception:
        return False
    return True


def challenge_answer(challenge: str) -> str:
    """The response a user who saw `challenge` would give: the announced
    digits for a "say the number" prompt, otherwise a description of the
    movement (verified from the frames themselves, not from this text)."""
    match = re.search(r"\d+", challenge)
    if match and "number" in challenge.lower():
        return match.group()
    return "performed: " + challenge.lower()


# Ways the demo can deliberately break the transaction binding, to show that
# each one is caught cryptographically before any AI runs.
TAMPER_MODES = {
    "stale_timestamp": "Evidence signed 2 minutes ago (outside the 30 s freshness window)",
    "swap_frames": "Different frames submitted than the ones that were signed",
    "reuse_nonce": "Second submission on an already-used session nonce",
    "wrong_challenge": "Wrong answer to the liveness challenge (pre-recorded evidence)",
    "corrupt_channel": "One bit flipped in the ML-KEM/AES-GCM sealed payload in transit",
}


def run_verification(
    frames: list,
    frame_timestamps: list[float] | None = None,
    challenge_response: str | None = None,
    session: dict | None = None,
    tamper: str | None = None,
    sealed: bool | None = None,
) -> tuple[dict, dict]:
    """Full client flow for one submission: start a session (unless one is
    given), hash the frames, have the evidence signed (ML-DSA, see README
    Assumption #2), and submit - over the sealed ML-KEM + AES-256-GCM
    channel when this client has liboqs, else in plaintext. Returns
    (session, verify_response). `tamper` selects one of TAMPER_MODES."""
    from client_demo.frame_utils import frame_to_png_bytes
    from crypto.channel import evidence_hash_of

    session = session or session_start()
    session_id = session["session_id"]
    if challenge_response is None:
        challenge_response = challenge_answer(session["challenge"])
    if tamper == "wrong_challenge":
        challenge_response = "0000" if "number" in session["challenge"].lower() else ""

    frame_bytes = [frame_to_png_bytes(f) for f in frames]
    evidence_hash = evidence_hash_of(frame_bytes).hex()
    timestamp = now_iso(-120 if tamper == "stale_timestamp" else 0)
    signature = sign_evidence(session_id, evidence_hash, timestamp, challenge_response)["signature"]

    if tamper == "swap_frames":
        # e.g. a different face swapped in after a genuine one was signed
        frame_bytes = [frame_to_png_bytes(np.ascontiguousarray(f[:, ::-1])) for f in frames]
    payload = {
        "evidence_hash": evidence_hash,
        "timestamp": timestamp,
        "challenge_response": challenge_response,
        "signature": signature,
        "frames_b64": [base64.b64encode(b).decode("ascii") for b in frame_bytes],
        "frame_timestamps": frame_timestamps,
    }

    sealed = can_seal() if sealed is None else sealed
    submit = _submit_sealed if sealed else _submit_plain
    if tamper == "reuse_nonce":
        submit(session, payload)  # first, legitimate use of the nonce
    return session, submit(session, payload, corrupt=(tamper == "corrupt_channel"))


def _submit_plain(session: dict, payload: dict, corrupt: bool = False) -> dict:
    if corrupt:
        raise ApiError("corrupt_channel needs the sealed channel (liboqs on the client)")
    return _request("POST", f"/session/{session['session_id']}/verify", json=payload)


def _submit_sealed(session: dict, payload: dict, corrupt: bool = False) -> dict:
    from crypto.channel import seal_payload
    from crypto.kem import client_encapsulate

    kem_ciphertext, shared_secret = client_encapsulate(bytes.fromhex(session["kem_public_key"]), alg=session["kem_alg"])
    aead_nonce, ciphertext = seal_payload(
        shared_secret, base64.b64decode(session["nonce"]), session["session_id"], json.dumps(payload).encode("utf-8")
    )
    if corrupt:
        ciphertext = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    result = _request(
        "POST",
        f"/session/{session['session_id']}/verify-sealed",
        json={
            "kem_ciphertext": kem_ciphertext.hex(),
            "aead_nonce": base64.b64encode(aead_nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
    )
    result["sealed_bytes"] = {"kem_ciphertext": len(kem_ciphertext), "aes_gcm_ciphertext": len(ciphertext)}
    return result
