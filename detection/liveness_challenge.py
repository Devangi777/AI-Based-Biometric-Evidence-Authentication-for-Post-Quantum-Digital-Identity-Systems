"""Liveness-challenge fulfilment check - spec Section 7 step 6d.

binding/session_binding.py requires this as an injectable `challenge_check`
callable rather than implementing it directly, because verifying it needs
the captured frames, not just the (nonce, timestamp, challenge_response)
tuple everything else in that module works with. This module supplies the
real implementation server/main.py wires in (replacing
`placeholder_challenge_check`).

Two challenge types (server/session_store.py's CHALLENGE_PROMPTS) get two
different treatments:
- "Say the number ####" - verified by string match against the announced
  digits inside `challenge_response`. This prototype has no ASR/audio
  pipeline (Section 4's tech stack doesn't include one), so a spoken digit
  can only be checked via what the client claims it heard back - weaker
  than real speech verification, and documented as such rather than hidden.
- "Turn your head left/right" / "Nod your head" - verified via MediaPipe
  Face Mesh nose-tip displacement across the supplied frames, when
  MediaPipe is available (same optional-dependency pattern as
  detection/morph_detector.py); falls back to a non-empty-response check
  otherwise.
"""
from __future__ import annotations

import logging
import re

import numpy as np

logger = logging.getLogger(__name__)

_DIGITS_RE = re.compile(r"\d+")
_NOSE_TIP_LANDMARK = 1  # MediaPipe Face Mesh canonical nose-tip index
_MOTION_THRESHOLD_FRACTION_OF_FACE_WIDTH = 0.06


def verify_challenge(challenge: str, challenge_response: str, frames: list[np.ndarray] | None = None) -> bool:
    return evaluate_challenge(challenge, challenge_response, frames)[0]


def evaluate_challenge(
    challenge: str, challenge_response: str, frames: list[np.ndarray] | None = None
) -> tuple[bool, dict]:
    """Like verify_challenge, plus what was measured, so a rejection can be
    explained (e.g. how far the head actually moved)."""
    challenge_lower = (challenge or "").lower()

    if "say the number" in challenge_lower:
        expected = _DIGITS_RE.search(challenge)
        given = _DIGITS_RE.search(challenge_response or "")
        ok = bool(expected and given and expected.group() == given.group())
        return ok, {
            "kind": "number",
            "expected": expected.group() if expected else None,
            "given": given.group() if given else None,
        }

    if frames and len(frames) >= 2 and ("turn" in challenge_lower or "nod" in challenge_lower):
        motion = _max_landmark_motion(frames)
        if motion is not None:
            return motion >= _MOTION_THRESHOLD_FRACTION_OF_FACE_WIDTH, {
                "kind": "movement",
                "motion": motion,
                "required": _MOTION_THRESHOLD_FRACTION_OF_FACE_WIDTH,
            }

    # Fallback: no frames, MediaPipe unavailable, or an unrecognized
    # challenge type - can only check that some response was submitted.
    ok = bool(challenge_response and challenge_response.strip())
    return ok, {"kind": "response_only", "frames": len(frames or [])}


def _max_landmark_motion(frames: list[np.ndarray]) -> float | None:
    try:
        import mediapipe as mp
    except Exception as exc:
        logger.warning("Liveness challenge: MediaPipe unavailable (%s); using response-only fallback.", exc)
        return None

    face_mesh = mp.solutions.face_mesh.FaceMesh(static_image_mode=True, max_num_faces=1, refine_landmarks=False)
    positions = []
    face_widths = []
    try:
        for frame in frames:
            result = face_mesh.process(frame)
            if not result.multi_face_landmarks:
                continue
            landmarks = result.multi_face_landmarks[0].landmark
            h, w = frame.shape[:2]
            xs = [lm.x * w for lm in landmarks]
            positions.append((landmarks[_NOSE_TIP_LANDMARK].x * w, landmarks[_NOSE_TIP_LANDMARK].y * h))
            face_widths.append(max(xs) - min(xs))
    finally:
        face_mesh.close()

    if len(positions) < 2:
        return None

    face_width = float(np.mean(face_widths)) or 1.0
    xs, ys = zip(*positions)
    motion_px = float(np.hypot(max(xs) - min(xs), max(ys) - min(ys)))
    return motion_px / face_width
