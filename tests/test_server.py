"""FastAPI server tests: session lifecycle, crypto, Section 7 transaction
binding, and the full AI-detection + fusion pipeline wired into /verify.

`/health` is designed to degrade gracefully (not raise) when liboqs is
unavailable, so it's tested unconditionally. Everything that creates a
session needs a real ML-KEM/ML-DSA keypair and is skipped without liboqs -
see tests/conftest.py. Fusion's exact ACCEPT/REJECT outcome on mock-mode
heuristic scores of synthetic noise isn't asserted here (that's
deterministic-input territory - see tests/test_fusion.py); these tests only
assert that the pipeline *ran* and returned well-formed output once binding
passes.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from io import BytesIO

import numpy as np
from fastapi.testclient import TestClient
from PIL import Image

from conftest import skip_if_no_oqs

from server.main import app

client = TestClient(app)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _frame_b64(seed: int = 0) -> str:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    buf = BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _challenge_response_for(challenge: str) -> str:
    """Whatever `verify_challenge` (detection/liveness_challenge.py) needs
    to accept this specific challenge without real motion frames: the exact
    announced digits for a "say the number" challenge, or any non-empty
    string for a turn/nod challenge (which falls back to a response-present
    check without motion frames)."""
    match = re.search(r"\d+", challenge)
    if match and "number" in challenge.lower():
        return match.group()
    return "done"


def test_health_reports_status_without_raising():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in {"ok", "degraded"}
    assert "kem_alg" in body and "sig_alg" in body
    assert "liboqs_ready" in body


@skip_if_no_oqs
class TestSessionFlow:
    def test_session_start_returns_expected_fields(self):
        resp = client.post("/session/start")
        assert resp.status_code == 200
        body = resp.json()
        for field in ("session_id", "nonce", "challenge", "kem_public_key", "client_public_key"):
            assert body[field]

    def test_channel_establish_shared_secret_matches(self):
        session = client.post("/session/start").json()
        resp = client.post(f"/session/{session['session_id']}/channel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["shared_secret_established"] is True
        assert "total_ms" in body["timing_ms"]

    def test_sign_then_verify_runs_full_pipeline(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        challenge_response = _challenge_response_for(session["challenge"])

        evidence_hash = "00" * 32
        timestamp = _now_iso()
        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": evidence_hash, "timestamp": timestamp, "challenge_response": challenge_response},
        )
        assert sign_resp.status_code == 200
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": evidence_hash,
                "timestamp": timestamp,
                "challenge_response": challenge_response,
                "signature": signature,
                "frames_b64": [_frame_b64(seed=1)],
            },
        )
        assert verify_resp.status_code == 200
        body = verify_resp.json()
        assert body["binding_accepted"] is True
        assert body["binding_checks"] == {
            "signature_valid": True,
            "nonce_unused": True,
            "timestamp_fresh": True,
            "challenge_fulfilled": True,
        }
        assert body["detection_ran"] is True
        assert set(body["detection_scores"].keys()) == {
            "presentation_attack",
            "morph",
            "deepfake",
            "replay",
            "injection",
        }
        assert 0.0 <= body["fused_score"] <= 1.0
        assert isinstance(body["accepted"], bool)
        assert "total_ms" in body["timing_ms"]

    def test_verify_without_frames_after_binding_passes_is_400(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        challenge_response = _challenge_response_for(session["challenge"])
        timestamp = _now_iso()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": timestamp, "challenge_response": challenge_response},
        )
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": "00" * 32,
                "timestamp": timestamp,
                "challenge_response": challenge_response,
                "signature": signature,
                # frames_b64 omitted
            },
        )
        assert verify_resp.status_code == 400

    def test_verify_rejects_mismatched_evidence_hash_before_detection(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        timestamp = _now_iso()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": timestamp, "challenge_response": "done"},
        )
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": "11" * 32,  # different evidence than what was signed
                "timestamp": timestamp,
                "challenge_response": "done",
                "signature": signature,
            },
        )
        assert verify_resp.status_code == 200
        body = verify_resp.json()
        assert body["binding_accepted"] is False
        assert body["binding_checks"]["signature_valid"] is False
        assert body["detection_ran"] is False
        assert body["accepted"] is False

    def test_verify_rejects_stale_timestamp_before_detection(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        stale_timestamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": stale_timestamp, "challenge_response": "done"},
        )
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": "00" * 32,
                "timestamp": stale_timestamp,
                "challenge_response": "done",
                "signature": signature,
            },
        )
        body = verify_resp.json()
        assert body["binding_accepted"] is False
        assert body["binding_checks"]["timestamp_fresh"] is False
        # a stale submission is still cryptographically valid on its own terms
        assert body["binding_checks"]["signature_valid"] is True
        assert body["detection_ran"] is False

    def test_verify_rejects_reused_nonce(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        challenge_response = _challenge_response_for(session["challenge"])
        timestamp = _now_iso()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": timestamp, "challenge_response": challenge_response},
        )
        signature = sign_resp.json()["signature"]
        verify_payload = {
            "evidence_hash": "00" * 32,
            "timestamp": timestamp,
            "challenge_response": challenge_response,
            "signature": signature,
            "frames_b64": [_frame_b64(seed=2)],
        }

        first = client.post(f"/session/{session_id}/verify", json=verify_payload)
        assert first.json()["binding_accepted"] is True

        # Replaying the exact same (already-signed, already-verified)
        # evidence against the same session must be rejected - this is the
        # core anti-replay property from spec Section 7.
        second = client.post(f"/session/{session_id}/verify", json=verify_payload)
        body = second.json()
        assert body["binding_accepted"] is False
        assert body["binding_checks"]["nonce_unused"] is False
        assert body["detection_ran"] is False

    def test_verify_unknown_session_returns_404(self):
        resp = client.post(
            "/session/does-not-exist/verify",
            json={"evidence_hash": "00" * 32, "timestamp": _now_iso(), "signature": "00"},
        )
        assert resp.status_code == 404

    def test_end_session_closes_it(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        resp = client.delete(f"/session/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["closed"] is True
        # session no longer usable
        assert client.post(f"/session/{session_id}/channel").status_code == 404
