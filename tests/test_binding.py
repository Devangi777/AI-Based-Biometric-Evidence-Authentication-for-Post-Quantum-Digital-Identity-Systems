"""Unit tests for binding/session_binding.py in isolation from the FastAPI
server (spec Definition of Done: "Unit tests: ... session-binding freshness
logic"). Needs a real ML-DSA signer to produce a valid signature to test
against, so is skipped without liboqs - see tests/conftest.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import skip_if_no_oqs

from binding.session_binding import (
    check_transaction_binding,
    parse_timestamp,
    placeholder_challenge_check,
)


def test_parse_timestamp_accepts_trailing_z():
    dt = parse_timestamp("2026-09-07T12:00:00Z")
    assert dt.tzinfo is not None
    assert dt.year == 2026 and dt.hour == 12


def test_placeholder_challenge_check_rejects_empty_response():
    assert placeholder_challenge_check("turn left", "") is False
    assert placeholder_challenge_check("turn left", "   ") is False
    assert placeholder_challenge_check("turn left", "done") is True


@skip_if_no_oqs
class TestCheckTransactionBinding:
    def _sign(self, signer, nonce, timestamp, challenge_response, evidence_hash=b"\x00" * 32):
        from crypto.signature import build_binding_payload

        payload = build_binding_payload(evidence_hash, nonce, timestamp, challenge_response)
        return signer.sign(payload), evidence_hash

    def test_all_checks_pass_for_a_valid_fresh_submission(self):
        from crypto.signature import SignerIdentity

        with SignerIdentity(alg="ML-DSA-65") as signer:
            nonce = b"\x01" * 32
            timestamp = datetime.now(timezone.utc).isoformat()
            signature, evidence_hash = self._sign(signer, nonce, timestamp, "7")

            result = check_transaction_binding(
                session_nonce=nonce,
                session_challenge="say 7",
                client_public_key=signer.public_key,
                sig_alg="ML-DSA-65",
                evidence_hash=evidence_hash,
                timestamp=timestamp,
                challenge_response="7",
                signature=signature,
                nonce_already_used=False,
            )

        assert result.accepted is True
        assert result.checks == {
            "signature_valid": True,
            "nonce_unused": True,
            "timestamp_fresh": True,
            "challenge_fulfilled": True,
        }
        assert result.reasons == []

    def test_rejects_stale_timestamp_outside_freshness_window(self):
        from crypto.signature import SignerIdentity

        with SignerIdentity(alg="ML-DSA-65") as signer:
            nonce = b"\x02" * 32
            stale_timestamp = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
            signature, evidence_hash = self._sign(signer, nonce, stale_timestamp, "7")

            result = check_transaction_binding(
                session_nonce=nonce,
                session_challenge="say 7",
                client_public_key=signer.public_key,
                sig_alg="ML-DSA-65",
                evidence_hash=evidence_hash,
                timestamp=stale_timestamp,
                challenge_response="7",
                signature=signature,
                nonce_already_used=False,
                freshness_window_seconds=30,
            )

        assert result.accepted is False
        assert result.checks["timestamp_fresh"] is False
        assert result.checks["signature_valid"] is True  # only freshness should fail

    def test_rejects_already_used_nonce(self):
        from crypto.signature import SignerIdentity

        with SignerIdentity(alg="ML-DSA-65") as signer:
            nonce = b"\x03" * 32
            timestamp = datetime.now(timezone.utc).isoformat()
            signature, evidence_hash = self._sign(signer, nonce, timestamp, "7")

            result = check_transaction_binding(
                session_nonce=nonce,
                session_challenge="say 7",
                client_public_key=signer.public_key,
                sig_alg="ML-DSA-65",
                evidence_hash=evidence_hash,
                timestamp=timestamp,
                challenge_response="7",
                signature=signature,
                nonce_already_used=True,
            )

        assert result.accepted is False
        assert result.checks["nonce_unused"] is False

    def test_rejects_empty_challenge_response(self):
        from crypto.signature import SignerIdentity

        with SignerIdentity(alg="ML-DSA-65") as signer:
            nonce = b"\x04" * 32
            timestamp = datetime.now(timezone.utc).isoformat()
            signature, evidence_hash = self._sign(signer, nonce, timestamp, "")

            result = check_transaction_binding(
                session_nonce=nonce,
                session_challenge="say 7",
                client_public_key=signer.public_key,
                sig_alg="ML-DSA-65",
                evidence_hash=evidence_hash,
                timestamp=timestamp,
                challenge_response="",
                signature=signature,
                nonce_already_used=False,
            )

        assert result.accepted is False
        assert result.checks["challenge_fulfilled"] is False

    def test_custom_challenge_check_is_used(self):
        from crypto.signature import SignerIdentity

        def always_reject(challenge: str, response: str) -> bool:
            return False

        with SignerIdentity(alg="ML-DSA-65") as signer:
            nonce = b"\x05" * 32
            timestamp = datetime.now(timezone.utc).isoformat()
            signature, evidence_hash = self._sign(signer, nonce, timestamp, "7")

            result = check_transaction_binding(
                session_nonce=nonce,
                session_challenge="say 7",
                client_public_key=signer.public_key,
                sig_alg="ML-DSA-65",
                evidence_hash=evidence_hash,
                timestamp=timestamp,
                challenge_response="7",
                signature=signature,
                nonce_already_used=False,
                challenge_check=always_reject,
            )

        assert result.accepted is False
        assert result.checks["challenge_fulfilled"] is False
