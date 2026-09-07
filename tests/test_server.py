"""FastAPI server tests: session lifecycle + crypto-only sign/verify.

`/health` is designed to degrade gracefully (not raise) when liboqs is
unavailable, so it's tested unconditionally. Everything that creates a
session needs a real ML-KEM/ML-DSA keypair and is skipped without liboqs -
see tests/conftest.py.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import skip_if_no_oqs

from server.main import app

client = TestClient(app)


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
        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": evidence_hash, "timestamp": "2026-09-07T00:00:00Z", "challenge_response": "7"},
        )
        assert sign_resp.status_code == 200
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": evidence_hash,
                "timestamp": "2026-09-07T00:00:00Z",
                "challenge_response": "7",
                "signature": signature,
            },
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["signature_valid"] is True

    def test_verify_rejects_mismatched_evidence_hash(self):
        session = client.post("/session/start").json()
        session_id = session["session_id"]

        sign_resp = client.post(
            f"/session/{session_id}/evidence",
            json={"evidence_hash": "00" * 32, "timestamp": "2026-09-07T00:00:00Z", "challenge_response": "7"},
        )
        signature = sign_resp.json()["signature"]

        verify_resp = client.post(
            f"/session/{session_id}/verify",
            json={
                "evidence_hash": "11" * 32,  # different evidence than what was signed
                "timestamp": "2026-09-07T00:00:00Z",
                "challenge_response": "7",
                "signature": signature,
            },
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["signature_valid"] is False

    def test_verify_unknown_session_returns_404(self):
        resp = client.post(
            "/session/does-not-exist/verify",
            json={"evidence_hash": "00" * 32, "timestamp": "2026-09-07T00:00:00Z", "signature": "00"},
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
