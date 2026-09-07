"""Thin HTTP client for the FastAPI server (server/main.py).

All PQC operations happen server-side in this prototype (README.md
"Assumptions" #2) - this module only does plain HTTP calls plus local
SHA-256 hashing of captured evidence bytes (Section 3: the client computes
`evidence_hash = SHA-256(frame_bytes)` itself; that step needs no PQC
library, so it stays here rather than moving server-side).
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

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


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
