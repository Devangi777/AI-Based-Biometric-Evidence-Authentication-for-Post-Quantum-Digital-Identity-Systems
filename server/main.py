"""FastAPI server: session lifecycle, crypto (ML-KEM/ML-DSA), Section 7
transaction-binding enforcement, and the AI attack-detection + fusion
pipeline (spec Section 3's full server-side flow: KEM decap -> DSA verify ->
AI detection pipeline -> decision engine).

See README.md "Assumptions" #2 for why both the "client" ML-DSA signer and
the "server" ML-DSA verifier live in this one process: the Streamlit demo
client has no native liboqs build available on Windows, so this server
exposes distinct client-role and server-role endpoints instead.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import logging
import time

import numpy as np
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, HTTPException
from PIL import Image
from pydantic import BaseModel, Field

from binding.session_binding import check_transaction_binding
from crypto.channel import evidence_hash_of, open_payload
from crypto.kem import client_encapsulate, derive_channel_key, kem_details
from crypto.signature import build_binding_payload, sig_details
from detection.deepfake_detector import DeepfakeDetector
from detection.fusion import fuse
from detection.injection_detector import InjectionDetector
from detection.liveness_challenge import evaluate_challenge
from detection.morph_detector import MorphDetector
from detection.presentation_attack import PresentationAttackDetector
from detection.replay_detector import store as replay_store
from server.config import settings
from server.explain import explain
from server.session_store import Session, nonce_b64, store

logger = logging.getLogger(__name__)

app = FastAPI(title="PQ-Biometric-Auth Server", version="0.1.0")

# Process-wide detector instances (spec Section 6: pretrained-first, with an
# automatic mock-mode fallback logged per-module if a checkpoint/dependency
# is unavailable - see detection/README-models.md). Instantiated once at
# import time rather than per-request since loading a real checkpoint would
# be too slow to redo on every submission.
_pad_detector = PresentationAttackDetector(mode=settings.detection_mode, device=settings.detector_device)
_morph_detector = MorphDetector(mode=settings.detection_mode, device=settings.detector_device)
_deepfake_detector = DeepfakeDetector(mode=settings.detection_mode, device=settings.detector_device)
_injection_detector = InjectionDetector(mode=settings.detection_mode, device=settings.detector_device)

_FUSION_WEIGHTS = {
    "presentation_attack": settings.weight_presentation_attack,
    "morph": settings.weight_morph,
    "deepfake": settings.weight_deepfake,
    "replay": settings.weight_replay,
    "injection": settings.weight_injection,
}
_FUSION_THRESHOLDS = {
    "presentation_attack": settings.threshold_presentation_attack,
    "morph": settings.threshold_morph,
    "deepfake": settings.threshold_deepfake,
    "replay": settings.threshold_replay,
    "injection": settings.threshold_injection,
}


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
    frames_b64: list[str] = Field(
        default_factory=list,
        description="base64-encoded JPEG/PNG frames in temporal order; required only if binding checks pass",
    )
    frame_timestamps: list[float] | None = Field(
        default=None, description="unix timestamps per frame, for the injection detector's timing heuristic"
    )


class SealedVerifyRequest(BaseModel):
    kem_ciphertext: str = Field(description="hex-encoded ML-KEM ciphertext from the client's encapsulation")
    aead_nonce: str = Field(description="base64-encoded 12-byte AES-GCM nonce")
    ciphertext: str = Field(description="base64-encoded AES-256-GCM ciphertext+tag of a VerifyRequest JSON")


class VerifyResponse(BaseModel):
    session_id: str
    channel: str = Field(default="plaintext", description="how the payload reached the server")
    binding_accepted: bool = Field(description="True only if ALL Section 7 step-6 checks pass")
    binding_checks: dict[str, bool]
    binding_reasons: list[str]
    detection_ran: bool = Field(description="False if rejected at the binding stage, before AI detection runs")
    detection_scores: dict[str, float] | None = None
    detection_is_mock: dict[str, bool] | None = None
    detection_details: dict[str, dict] | None = Field(default=None, description="per-module diagnostic signals")
    fused_score: float | None = None
    below_threshold_modules: list[str] | None = None
    accepted: bool = Field(description="Final ACCEPT/REJECT decision")
    reason: str
    explanations: list[str] = Field(default_factory=list, description="plain-language reasons for the decision")
    liveness: dict | None = Field(default=None, description="what the liveness-challenge check measured")
    timing_ms: dict[str, float]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _get_session_or_404(session_id: str) -> Session:
    session = store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Unknown session_id {session_id!r}")
    return session


def _decode_frame_bytes(frames_b64: list[str]) -> list[bytes]:
    try:
        return [base64.b64decode(b64, validate=True) for b64 in frames_b64]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"frames_b64 must be base64: {exc}") from exc


def _decode_frames(frame_bytes: list[bytes]) -> list[np.ndarray]:
    frames = []
    for i, raw in enumerate(frame_bytes):
        try:
            image = Image.open(io.BytesIO(raw)).convert("RGB")
            frames.append(np.array(image))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not decode frames_b64[{i}]: {exc}") from exc
    return frames


def _json_safe(details: dict) -> dict:
    """Detector details as plain JSON numbers/strings (numpy scalars and
    imagehash objects aren't serializable by pydantic as-is)."""
    safe = {}
    for key, value in details.items():
        if isinstance(value, (bool, str)) or value is None:
            safe[key] = value
        elif isinstance(value, (int, float, np.integer, np.floating)):
            safe[key] = round(float(value), 4)
        elif isinstance(value, list):
            safe[key] = [round(float(v), 4) for v in value]
        else:
            safe[key] = str(value)
    return safe


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

    payload = build_binding_payload(evidence_hash, session.nonce, req.timestamp, req.challenge_response)

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
    """Plaintext variant of the verification pipeline, for clients without
    liboqs (see /verify-sealed for the ML-KEM + AES-256-GCM channel)."""
    session = _get_session_or_404(session_id)
    return _verify_core(session_id, session, req, timing_ms={}, channel="plaintext")


@app.post("/session/{session_id}/verify-sealed", response_model=VerifyResponse)
def verify_evidence_sealed(session_id: str, req: SealedVerifyRequest) -> VerifyResponse:
    """Verification over the post-quantum channel: the client encapsulated
    against this session's ML-KEM public key and encrypted the VerifyRequest
    JSON with AES-256-GCM under k = HKDF-SHA256(K, salt=session nonce), with
    the session_id as associated data. The server decapsulates, derives the
    same k and decrypts. Any tampering with the KEM ciphertext, the AEAD
    nonce/ciphertext, or a submission under another session's id fails GCM
    authentication and is rejected without running any further checks."""
    session = _get_session_or_404(session_id)

    try:
        kem_ciphertext = bytes.fromhex(req.kem_ciphertext)
        aead_nonce = base64.b64decode(req.aead_nonce)
        ciphertext = base64.b64decode(req.ciphertext)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="kem_ciphertext must be hex; aead_nonce/ciphertext base64") from exc

    t0 = time.perf_counter()
    try:
        shared_secret = session.kem.decapsulate(kem_ciphertext)
    except Exception:
        shared_secret = None
    t1 = time.perf_counter()

    plaintext = None
    if shared_secret is not None:
        try:
            plaintext = open_payload(shared_secret, session.nonce, session_id, aead_nonce, ciphertext)
        except InvalidTag:
            plaintext = None
    t2 = time.perf_counter()
    timing_ms = {"kem_decapsulate_ms": (t1 - t0) * 1000, "aead_decrypt_ms": (t2 - t1) * 1000}

    if plaintext is None:
        session.nonce_used = True
        reason = "sealed payload failed ML-KEM decapsulation / AES-256-GCM authentication (tampered or wrong session)"
        timing_ms["total_ms"] = sum(timing_ms.values())
        return VerifyResponse(
            session_id=session_id,
            channel="ML-KEM-768 + AES-256-GCM",
            binding_accepted=False,
            binding_checks={"channel_authentic": False},
            binding_reasons=[reason],
            detection_ran=False,
            accepted=False,
            reason="rejected at channel stage: " + reason,
            explanations=explain(accepted=False, binding_checks={"channel_authentic": False}, binding_reasons=[reason]),
            timing_ms=timing_ms,
        )

    try:
        inner = VerifyRequest.model_validate_json(plaintext)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"decrypted payload is not a valid VerifyRequest: {exc}") from exc
    return _verify_core(session_id, session, inner, timing_ms=timing_ms, channel=f"{settings.kem_alg} + AES-256-GCM")


def _verify_core(session_id: str, session: Session, req: VerifyRequest, timing_ms: dict, channel: str) -> VerifyResponse:
    """Full spec Section 3 server-side pipeline: Section 7 step-6 transaction
    binding (signature, nonce single-use, timestamp freshness, challenge
    fulfilment, plus that the submitted frames are the evidence that was
    signed) - only if ALL of those pass does the submission proceed to the
    AI attack-detection pipeline (5 detectors) and the fusion decision
    engine, per Section 7 step 7 ("Only if all four checks pass does the
    evidence proceed to the AI attack-detection pipeline")."""
    try:
        evidence_hash = bytes.fromhex(req.evidence_hash)
        signature = bytes.fromhex(req.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="evidence_hash and signature must be hex-encoded") from exc

    frame_bytes = _decode_frame_bytes(req.frames_b64)
    frames = _decode_frames(frame_bytes)

    liveness_ms = 0.0
    liveness: dict = {}

    def timed_challenge_check(challenge: str, response: str) -> bool:
        # The liveness check is AI (MediaPipe head-motion), not cryptography;
        # timed separately so binding_check_ms reports only the crypto and
        # bookkeeping checks. Its measurements are kept for the explanation.
        nonlocal liveness_ms
        start = time.perf_counter()
        try:
            ok, measured = evaluate_challenge(challenge, response, frames)
            liveness.update(measured)
            return ok
        finally:
            liveness_ms = (time.perf_counter() - start) * 1000

    t0 = time.perf_counter()
    binding_result = check_transaction_binding(
        session_nonce=session.nonce,
        session_challenge=session.challenge,
        client_public_key=session.client_signer.public_key,
        sig_alg=settings.sig_alg,
        evidence_hash=evidence_hash,
        timestamp=req.timestamp,
        challenge_response=req.challenge_response,
        signature=signature,
        nonce_already_used=session.nonce_used,
        freshness_window_seconds=settings.freshness_window_seconds,
        challenge_check=timed_challenge_check,
    )
    # The signature covers evidence_hash, so the frames actually analysed
    # must be the ones that hash describes - otherwise an attacker could get
    # a genuine capture's hash signed and then submit different frames.
    # (Without frames there is nothing to compare; that case is a 400 below
    # once the remaining checks pass.)
    if frame_bytes:
        binding_result._fail(
            "evidence_matches_hash",
            hmac.compare_digest(evidence_hash_of(frame_bytes), evidence_hash),
            "submitted frames do not match the signed evidence_hash (evidence substituted after signing)",
        )
    t1 = time.perf_counter()

    # The nonce is single-use: this verify attempt consumes it regardless of
    # outcome, so a rejected submission can't be retried against the same
    # nonce (spec Section 7: "prevents replay ... nonce ... unique").
    session.nonce_used = True

    timing_ms["binding_check_ms"] = (t1 - t0) * 1000 - liveness_ms
    timing_ms["liveness_check_ms"] = liveness_ms

    if not binding_result.accepted:
        logger.info("session=%s binding_rejected reasons=%s", session_id, binding_result.reasons)
        timing_ms["total_ms"] = sum(timing_ms.values())
        return VerifyResponse(
            session_id=session_id,
            channel=channel,
            binding_accepted=False,
            binding_checks=binding_result.checks,
            binding_reasons=binding_result.reasons,
            detection_ran=False,
            accepted=False,
            reason="rejected at transaction-binding stage: " + "; ".join(binding_result.reasons),
            explanations=explain(
                accepted=False,
                binding_checks=binding_result.checks,
                binding_reasons=binding_result.reasons,
                liveness=liveness,
                challenge=session.challenge,
            ),
            liveness=_json_safe(liveness),
            timing_ms=timing_ms,
        )

    if not frames:
        raise HTTPException(status_code=400, detail="frames_b64 must contain at least one frame once binding checks pass")

    t2 = time.perf_counter()
    primary_frame = frames[0]
    detection_results = [
        _pad_detector.predict(primary_frame),
        _morph_detector.predict(primary_frame),
        _deepfake_detector.predict_video(frames),
        replay_store.check_and_record(primary_frame, session_id=session_id),
        _injection_detector.predict(primary_frame, frame_timestamps=req.frame_timestamps),
    ]
    t3 = time.perf_counter()

    fusion_result = fuse(
        detection_results,
        weights=_FUSION_WEIGHTS,
        per_module_thresholds=_FUSION_THRESHOLDS,
        accept_threshold=settings.fusion_accept_threshold,
    )
    t4 = time.perf_counter()

    timing_ms["detection_ms"] = (t3 - t2) * 1000
    timing_ms["fusion_ms"] = (t4 - t3) * 1000
    timing_ms["total_ms"] = sum(timing_ms.values())
    detection_details = {r.module: _json_safe(r.details) for r in detection_results}

    if fusion_result.accepted:
        reason = f"accepted (fused_score={fusion_result.fused_score:.2f} >= threshold={fusion_result.threshold})"
    else:
        reason = (
            f"rejected by fusion (fused_score={fusion_result.fused_score:.2f}, threshold={fusion_result.threshold}, "
            f"below_threshold_modules={fusion_result.below_threshold_modules})"
        )
    logger.info("session=%s decision=%s fused_score=%.3f", session_id, fusion_result.accepted, fusion_result.fused_score)

    return VerifyResponse(
        session_id=session_id,
        channel=channel,
        binding_accepted=True,
        binding_checks=binding_result.checks,
        binding_reasons=[],
        detection_ran=True,
        detection_scores=fusion_result.per_module_scores,
        detection_is_mock=fusion_result.per_module_is_mock,
        detection_details=detection_details,
        fused_score=fusion_result.fused_score,
        below_threshold_modules=fusion_result.below_threshold_modules,
        accepted=fusion_result.accepted,
        reason=reason,
        explanations=explain(
            accepted=fusion_result.accepted,
            binding_checks=binding_result.checks,
            binding_reasons=[],
            detection_scores=fusion_result.per_module_scores,
            detection_details=detection_details,
            below_threshold_modules=fusion_result.below_threshold_modules,
            fused_score=fusion_result.fused_score,
            accept_threshold=fusion_result.threshold,
        ),
        liveness=_json_safe(liveness),
        timing_ms=timing_ms,
    )


@app.post("/demo/reset-replay-store")
def reset_replay_store() -> dict:
    """Forget previously seen evidence so a demo can be rehearsed with the
    same genuine sample. Disabled unless DEMO_MODE=true: in production this
    would let anyone erase replay protection."""
    if not settings.demo_mode:
        raise HTTPException(status_code=403, detail="only available with DEMO_MODE=true")
    replay_store.clear()
    return {"replay_store_cleared": True}


@app.delete("/session/{session_id}")
def end_session(session_id: str) -> dict:
    _get_session_or_404(session_id)
    store.delete(session_id)
    return {"session_id": session_id, "closed": True}
