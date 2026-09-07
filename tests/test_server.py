"""FastAPI server tests: session lifecycle, crypto, and Section 7
transaction-binding enforcement (nonce single-use, freshness, signature).

`/health` is designed to degrade gracefully (not raise) when liboqs is
unavailable, so it's tested unconditionally. Everything that creates a
session needs a real ML-KEM/ML-DSA keypair and is skipped without liboqs -
see tests/conftest.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from conftest import skip_if_no_oqs

from server.main import app

client = TestClient(app)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    def test_sign_then_verify_succeeds(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]

        evidence_hash = "00" * 32
        timestamp = _now_iso()
        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": evidence_hash, "timestamp": timestamp, "challenge_response": "7"},
        )
        assert sign_resp.status_code == 200
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": evidence_hash,
                "timestamp": timestamp,
                "challenge_response": "7",
                "signature": signature,
            },
        )
        assert verify_resp.status_code == 200
        body = verify_resp.json()
        assert body["accepted"] is True
        assert body["checks"] == {
            "signature_valid": True,
            "nonce_unused": True,
            "timestamp_fresh": True,
            "challenge_fulfilled": True,
        }

    def test_verify_rejects_mismatched_evidence_hash(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        timestamp = _now_iso()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": timestamp, "challenge_response": "7"},
        )
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": "11" * 32,  # different evidence than what was signed
                "timestamp": timestamp,
                "challenge_response": "7",
                "signature": signature,
            },
        )
        assert verify_resp.status_code == 200
        body = verify_resp.json()
        assert body["accepted"] is False
        assert body["checks"]["signature_valid"] is False

    def test_verify_rejects_stale_timestamp(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        stale_timestamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": stale_timestamp, "challenge_response": "7"},
        )
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": "00" * 32,
                "timestamp": stale_timestamp,
                "challenge_response": "7",
                "signature": signature,
            },
        )
        body = verify_resp.json()
        assert body["accepted"] is False
        assert body["checks"]["timestamp_fresh"] is False
        # a stale submission is still cryptographically valid on its own terms
        assert body["checks"]["signature_valid"] is True

    def test_verify_rejects_reused_nonce(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]
        timestamp = _now_iso()

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": timestamp, "challenge_response": "7"},
        )
        signature = sign_resp.json()["signature"]
        verify_payload = {
            "evidence_hash": "00" * 32,
            "timestamp": timestamp,
            "challenge_response": "7",
            "signature": signature,
        }

        first = client.post(f"/session/{session_id}/verify", json=verify_payload)
        assert first.json()["accepted"] is True

        # Replaying the exact same (already-signed, already-verified)
        # evidence against the same session must be rejected - this is the
        # core anti-replay property from spec Section 7.
        second = client.post(f"/session/{session_id}/verify", json=verify_payload)
        body = second.json()
        assert body["accepted"] is False
        assert body["checks"]["nonce_unused"] is False

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
