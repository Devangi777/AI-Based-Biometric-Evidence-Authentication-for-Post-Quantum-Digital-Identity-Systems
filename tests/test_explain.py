"""server/explain.py: every rejection path yields a specific, plain-language reason."""
from __future__ import annotations

from server.explain import explain


def test_accept_has_single_summary():
    out = explain(accepted=True, binding_checks={"signature_valid": True}, binding_reasons=[], fused_score=0.91)
    assert len(out) == 1 and "0.91" in out[0]


def test_binding_failures_are_explained_before_detectors():
    out = explain(
        accepted=False,
        binding_checks={"signature_valid": True, "timestamp_fresh": False, "evidence_matches_hash": False},
        binding_reasons=["timestamp is 120.4s old, outside the 30s freshness window"],
        detection_scores={"replay": 0.0},
        below_threshold_modules=["replay"],
    )
    assert len(out) == 2
    assert "120 s" in out[0] and "30 s" in out[0]
    assert "swapped after signing" in out[1]


def test_liveness_explanation_reports_measured_movement():
    out = explain(
        accepted=False,
        binding_checks={"challenge_fulfilled": False},
        binding_reasons=[],
        liveness={"kind": "movement", "motion": 0.02, "required": 0.06},
        challenge="Turn your head slightly left",
    )
    assert "2%" in out[0] and "6%" in out[0]


def test_presentation_attack_names_the_cues_that_fired():
    out = explain(
        accepted=False,
        binding_checks={},
        binding_reasons=[],
        detection_scores={"presentation_attack": 0.01},
        detection_details={"presentation_attack": {"face_black_level": 62, "face_sharpness": 7.3, "face_saturation": 47}},
        below_threshold_modules=["presentation_attack"],
        fused_score=0.77,
    )
    assert "62/255" in out[0] and "sharpness 7" in out[0] and "saturation 47" in out[0]


def test_injection_explains_machine_perfect_timing():
    out = explain(
        accepted=False,
        binding_checks={},
        binding_reasons=[],
        detection_scores={"injection": 0.2},
        detection_details={"injection": {"timing_checked": True, "frame_interval_jitter_ratio": 0.0, "block_boundary_energy_ratio": 1.7}},
        below_threshold_modules=["injection"],
    )
    assert "machine-perfect" in out[0] and "re-encoded" in out[0]


def test_low_fused_score_without_veto_is_explained():
    out = explain(accepted=False, binding_checks={}, binding_reasons=[], detection_scores={}, below_threshold_modules=[], fused_score=0.55)
    assert "0.55" in out[0]


def test_multiple_vetoes_lead_with_the_most_specific_reason():
    out = explain(
        accepted=False,
        binding_checks={},
        binding_reasons=[],
        detection_scores={"injection": 0.2, "morph": 0.0, "presentation_attack": 0.4},
        detection_details={},
        below_threshold_modules=["injection", "morph", "presentation_attack"],
    )
    assert out[0].startswith("Looks like a photo or screen") and len(out) == 3
