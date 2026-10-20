"""Plain-language explanations of a verification decision.

Turns the failed binding checks and vetoing detectors (plus the values each
one measured) into short sentences a non-expert can act on. Returned in the
API response as `explanations` and shown by the dashboard under every
REJECT. Numbers quoted here mirror the thresholds in detection/*.py.
"""
from __future__ import annotations

import re

_TIMESTAMP_AGE_RE = re.compile(r"timestamp is ([\d.]+)s old")
# Most specific explanation first when several detectors veto.
_DETECTOR_ORDER = ["replay", "presentation_attack", "deepfake", "morph", "injection"]


def explain(
    *,
    accepted: bool,
    binding_checks: dict[str, bool],
    binding_reasons: list[str],
    detection_scores: dict[str, float] | None = None,
    detection_details: dict[str, dict] | None = None,
    below_threshold_modules: list[str] | None = None,
    fused_score: float | None = None,
    accept_threshold: float = 0.6,
    liveness: dict | None = None,
    challenge: str = "",
) -> list[str]:
    if accepted:
        return ["Every check passed: the evidence was decrypted and authenticated, it belongs to this session "
                "and was captured within the last 30 s, the liveness challenge was performed, and all five "
                f"detectors judged it genuine (combined score {fused_score:.2f} ≥ {accept_threshold})."]

    reasons = [_explain_check(name, binding_reasons, liveness or {}, challenge)
               for name, ok in binding_checks.items() if not ok]
    if reasons:
        return reasons

    details = detection_details or {}
    vetoed = sorted(below_threshold_modules or [], key=lambda m: _DETECTOR_ORDER.index(m) if m in _DETECTOR_ORDER else 99)
    reasons = [_explain_detector(m, (detection_scores or {}).get(m, 0.0), details.get(m, {})) for m in vetoed]
    if not reasons and fused_score is not None:
        reasons.append(f"No single detector was certain it was an attack, but together they were not confident it "
                       f"is genuine: combined score {fused_score:.2f}, below the {accept_threshold} needed to accept.")
    return reasons


def _explain_check(name: str, binding_reasons: list[str], liveness: dict, challenge: str) -> str:
    if name == "channel_authentic":
        return ("The encrypted package failed its integrity check (AES-256-GCM tag), so it was altered in transit "
                "or encrypted for a different session. Nothing inside it was trusted.")
    if name == "signature_valid":
        return ("The ML-DSA signature does not match this session's evidence hash, one-time code, timestamp and "
                "challenge answer, so something was changed after it was signed.")
    if name == "nonce_unused":
        return ("This session's one-time code was already used. Each code allows exactly one submission, so the "
                "same evidence (or a retry) cannot be sent twice. Start a new session.")
    if name == "timestamp_fresh":
        age = next((m.group(1) for r in binding_reasons if (m := _TIMESTAMP_AGE_RE.search(r))), None)
        when = f"{float(age):.0f} s" if age else "too long"
        return (f"The evidence was captured {when} before it reached the server. Anything older than 30 s is "
                "treated as possibly pre-recorded.")
    if name == "evidence_matches_hash":
        return ("The frames received are not the ones whose SHA-256 fingerprint was signed: the evidence was "
                "swapped after signing.")
    if name == "challenge_fulfilled":
        return _explain_liveness(liveness, challenge)
    return f"Check '{name}' failed."


def _explain_liveness(liveness: dict, challenge: str) -> str:
    kind = liveness.get("kind")
    if kind == "number":
        given = liveness.get("given") or "nothing"
        return (f"Liveness challenge not met: the number given ({given}) is not the one requested "
                f"({liveness.get('expected')}). A pre-recorded video can't know a number chosen just now.")
    if kind == "movement":
        return (f"Liveness challenge not met: '{challenge}' asked for a head movement, but the head moved only "
                f"{liveness['motion']:.0%} of the face width during the recording (at least "
                f"{liveness['required']:.0%} is needed). If this is you: make the movement clearly, within the "
                "recording.")
    return "Liveness challenge not met: no response to the challenge was given."


def _explain_detector(module: str, score: float, d: dict) -> str:
    if module == "presentation_attack":
        cues = []
        if d.get("face_black_level", 0) > 25:
            cues.append(f"the darkest parts of the face are grey ({d['face_black_level']:.0f}/255) instead of black; "
                        "paper and screens can't show true black, while a live face has pupils and hair near 0")
        if d.get("face_sharpness", 99) < 15:
            cues.append(f"the face is very soft (sharpness {d['face_sharpness']:.0f}; live webcam faces measure 25+), "
                        "as when a photo or phone is held close to the camera")
        if d.get("face_saturation", 99) < 60:
            cues.append(f"colours are washed out (saturation {d['face_saturation']:.0f}; live faces measure 75+)")
        why = "; ".join(cues) or "the image has the overall look of a recaptured photo or screen"
        return (f"Looks like a photo or screen held up to the camera (presentation attack, score {score:.2f}): {why}. "
                "If this is you: light your face from the front and avoid a bright window behind you.")
    if module == "morph":
        cues = []
        if d.get("ghost_prominence", 0) >= 0.13:
            cues.append(f"a faint second outline of the face (ghosting strength {d['ghost_prominence']:.2f}), which "
                        "is what blending two faces leaves")
        if d.get("mirror_correlation", 0) >= 0.20:
            cues.append(f"fine skin texture is mirror-symmetric (correlation {d['mirror_correlation']:.2f}); real "
                        "faces are not")
        why = "; ".join(cues) or "blending artifacts in the face region"
        return (f"Looks like two faces blended into one (morph, score {score:.2f}): {why}. A strongly repeating "
                "pattern around the face (a screen's moiré, stripes, blinds) also causes this.")
    if module == "deepfake":
        hf = d.get("high_freq_ratio")
        measured = f"{hf:.0%} of the image's frequency content is very fine detail (camera images: about 35% or less)" if hf is not None else "unusual high-frequency content"
        return (f"Looks AI-generated (deepfake, score {score:.2f}): {measured}. Face generators leave this residue "
                "when they upsample their output.")
    if module == "replay":
        dist = d.get("best_match_hamming_distance")
        diff = f"{int(dist)} of 64 bits" if dist is not None else "a few bits"
        corr = d.get("detail_correlation")
        same = f", and its fine pixel detail matches at {corr:.2f}" if corr is not None else ""
        return (f"This is a resubmission of a capture the server has already seen: same picture structure "
                f"(perceptual-hash difference {diff}){same}, i.e. the same capture rather than a new one. "
                "A captured image cannot be reused, even a genuine one. Record a new clip instead.")
    if module == "injection":
        cues = []
        jitter = d.get("frame_interval_jitter_ratio")
        if d.get("timing_checked") and jitter is not None and jitter <= 0.02:
            cues.append(f"the frames arrive with machine-perfect timing (jitter {jitter:.1%}); a real camera never "
                        "delivers frames that evenly, but a video file or virtual camera does")
        elif d.get("timing_checked") and jitter is not None and jitter > 0.35:
            cues.append(f"frame timing is erratic (jitter {jitter:.0%}), as with dropped or duplicated frames")
        if d.get("block_boundary_energy_ratio", 0) > 1.6:
            cues.append(f"strong 8×8 compression blocks (ratio {d['block_boundary_energy_ratio']:.2f}) show the video "
                        "was re-encoded")
        why = "; ".join(cues) or "the stream does not behave like a live camera"
        return f"Looks like a video fed in instead of a live camera (injection, score {score:.2f}): {why}."
    return f"Detector '{module}' scored {score:.2f}, below 0.5."
