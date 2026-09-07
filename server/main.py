"""FastAPI server: session lifecycle + crypto-only evidence signing/verification.

No AI detection yet (added in later stages: binding/session_binding.py wires
in full nonce/freshness/challenge enforcement; detection/*.py + the fusion
engine add the AI attack-detection pipeline in front of the final decision).

See README.md "Assumptions" #2 for why both the "client" ML-DSA signer and
the "server" ML-DSA verifier live in this one process: the Streamlit demo
client has no native liboqs build available on Windows, so this server
exposes distinct client-role and server-role endpoints instead.
"""
from __future__ import annotations

import hashlib
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from crypto.kem import client_encapsulate, derive_channel_key, kem_details
from crypto.signature import build_binding_payload, sig_details, verify as sig_verify
from server.config import settings
from server.session_store import Session, nonce_b64, store

app = FastAPI(title="PQ-Biometric-Auth Server", version="0.1.0")


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class SessionStartResponse(BaseModel):
    session_id: str
    nonce: str = Field(description="base64-encoded session nonce")
    challenge: str
    kem_alg: str
    sig_alg: str
    kem_public_key: str = Field(description="hex-encoded ML-KEM public key")
    client_public_key: str = Field(description="hex-encoded ML-DSA public key of the demo client identity")
    issued_at: float
    freshness_window_seconds: int


class ChannelEstablishResponse(BaseModel):
    session_id: str
    kem_ciphertext: str = Field(description="hex-encoded ML-KEM ciphertext")
    shared_secret_established: bool
    channel_key_fingerprint: str = Field(description="first 8 bytes of the derived AES-256 key, hex, for demo display only")
    timing_ms: dict[str, float]


class EvidenceSignRequest(BaseModel):
    evidence_hash: str = Field(description="hex-encoded SHA-256 of the captured frame/video bytes")
    timestamp: str = Field(description="ISO-8601 capture timestamp")
    challenge_response: str = Field(default="", description="what the client claims it did to fulfil the liveness challenge")


class EvidenceSignResponse(BaseModel):
    session_id: str
    signature: str = Field(description="hex-encoded ML-DSA signature over the Section 7 binding payload")
    binding_payload_sha256: str
    timing_ms: dict[str, float]


class VerifyRequest(BaseModel):
    evidence_hash: str
    timestamp: str
    challenge_response: str = ""
    signature: str = Field(description="hex-encoded ML-DSA signature to verify")


class VerifyResponse(BaseModel):
    session_id: str
    signature_valid: bool
    reason: str
    timing_ms: dict[str, float]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _get_session_or_404(session_id: str) -> Session:
    session = store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Unknown session_id {session_id!r}")
    return session


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    liboqs_ready = True
    error = None
    try:
        kem_details(settings.kem_alg)
        sig_details(settings.sig_alg)
    except Exception as exc:  # pragma: no cover - environment dependent
        liboqs_ready = False
        error = str(exc)

    payload = {
        "status": "ok" if liboqs_ready else "degraded",
        "kem_alg": settings.kem_alg,
        "sig_alg": settings.sig_alg,
        "liboqs_ready": liboqs_ready,
    }
    if error:
        payload["error"] = error
    return payload


@app.post("/session/start", response_model=SessionStartResponse)
def session_start() -> SessionStartResponse:
    session = store.create()
    return SessionStartResponse(
        session_id=session.session_id,
        nonce=nonce_b64(session.nonce),
        challenge=session.challenge,
        kem_alg=settings.kem_alg,
        sig_alg=settings.sig_alg,
        kem_public_key=session.kem.public_key.hex(),
        client_public_key=session.client_signer.public_key.hex(),
        issued_at=session.created_at,
        freshness_window_seconds=settings.freshness_window_seconds,
    )


@app.post("/session/{session_id}/channel", response_model=ChannelEstablishResponse)
def establish_channel(session_id: str) -> ChannelEstablishResponse:
    session = _get_session_or_404(session_id)

    t0 = time.perf_counter()
    ciphertext, client_secret = client_encapsulate(session.kem.public_key, alg=settings.kem_alg)
    t1 = time.perf_counter()
    server_secret = session.kem.decapsulate(ciphertext)
    t2 = time.perf_counter()

    established = client_secret == server_secret
    session.kem_established = established
    channel_key = derive_channel_key(server_secret, salt=session.nonce)

    return ChannelEstablishResponse(
        session_id=session_id,
        kem_ciphertext=ciphertext.hex(),
        shared_secret_established=established,
        channel_key_fingerprint=channel_key[:8].hex(),
        timing_ms={
            "encapsulate_ms": (t1 - t0) * 1000,
            "decapsulate_ms": (t2 - t1) * 1000,
            "total_ms": (t2 - t0) * 1000,
        },
    )


@app.post("/session/{session_id}/evidence", response_model=EvidenceSignResponse)
def sign_evidence(session_id: str, req: EvidenceSignRequest) -> EvidenceSignResponse:
    session = _get_session_or_404(session_id)

    try:
        evidence_hash = bytes.fromhex(req.evidence_hash)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="evidence_hash must be hex-encoded") from exc

    payload = build_binding_payload(evidence_hash, session_id, req.timestamp, req.challenge_response)

    t0 = time.perf_counter()
    signature = session.client_signer.sign(payload)
    t1 = time.perf_counter()

    return EvidenceSignResponse(
        session_id=session_id,
        signature=signature.hex(),
        binding_payload_sha256=hashlib.sha256(payload).hexdigest(),
        timing_ms={"sign_ms": (t1 - t0) * 1000},
    )


@app.post("/session/{session_id}/verify", response_model=VerifyResponse)
def verify_evidence(session_id: str, req: VerifyRequest) -> VerifyResponse:
    """Crypto-only verification (signature validity). Nonce single-use,
    timestamp freshness window, and challenge-fulfilment checks are added in
    binding/session_binding.py and wired in here in a later stage."""
    session = _get_session_or_404(session_id)

    try:
        evidence_hash = bytes.fromhex(req.evidence_hash)
        signature = bytes.fromhex(req.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="evidence_hash and signature must be hex-encoded") from exc

    payload = build_binding_payload(evidence_hash, session_id, req.timestamp, req.challenge_response)

    t0 = time.perf_counter()
    valid = sig_verify(payload, signature, session.client_signer.public_key, alg=settings.sig_alg)
    t1 = time.perf_counter()

    return VerifyResponse(
        session_id=session_id,
        signature_valid=valid,
        reason="ML-DSA signature valid" if valid else "ML-DSA signature verification failed",
        timing_ms={"verify_ms": (t1 - t0) * 1000},
    )


@app.delete("/session/{session_id}")
def end_session(session_id: str) -> dict:
    _get_session_or_404(session_id)
    store.delete(session_id)
    return {"session_id": session_id, "closed": True}
