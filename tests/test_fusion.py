"""Unit tests for detection/fusion.py using controlled DetectionResult
inputs (not real detector output), so the ACCEPT/REJECT boundary logic is
tested deterministically regardless of mock-heuristic calibration.
"""
from __future__ import annotations

import pytest

from detection.base import DetectionResult
from detection.fusion import DEFAULT_ACCEPT_THRESHOLD, DEFAULT_WEIGHTS, fuse

ALL_GENUINE = [
    DetectionResult(module="presentation_attack", score=0.9, is_mock=True),
    DetectionResult(module="morph", score=0.9, is_mock=True),
    DetectionResult(module="deepfake", score=0.9, is_mock=True),
    DetectionResult(module="replay", score=1.0, is_mock=False),
    DetectionResult(module="injection", score=0.9, is_mock=True),
]


def test_all_high_scores_are_accepted():
    result = fuse(ALL_GENUINE)
    assert result.accepted is True
    assert result.fused_score >= DEFAULT_ACCEPT_THRESHOLD
    assert result.below_threshold_modules == []


def test_all_low_scores_are_rejected():
    results = [DetectionResult(module=r.module, score=0.1, is_mock=r.is_mock) for r in ALL_GENUINE]
    result = fuse(results)
    assert result.accepted is False
    assert result.fused_score < DEFAULT_ACCEPT_THRESHOLD


def test_single_module_veto_below_per_module_threshold():
    """A confident single-module attack signal (e.g. an exact replay hash
    match) must reject even if the weighted average alone would pass."""
    results = [
        DetectionResult(module="presentation_attack", score=0.95, is_mock=True),
        DetectionResult(module="morph", score=0.95, is_mock=True),
        DetectionResult(module="deepfake", score=0.95, is_mock=True),
        DetectionResult(module="replay", score=0.0, is_mock=False),  # exact replay match
        DetectionResult(module="injection", score=0.95, is_mock=True),
    ]
    thresholds = {m: 0.5 for m in DEFAULT_WEIGHTS}
    result = fuse(results, per_module_thresholds=thresholds)
    assert result.fused_score >= DEFAULT_ACCEPT_THRESHOLD  # weighted average alone would pass
    assert result.accepted is False  # but the veto still rejects
    assert result.below_threshold_modules == ["replay"]


def test_fused_score_is_weighted_average():
    weights = {"presentation_attack": 1.0}
    results = [DetectionResult(module="presentation_attack", score=0.42, is_mock=True)]
    result = fuse(results, weights=weights, accept_threshold=0.0)
    assert result.fused_score == pytest.approx(0.42)


def test_custom_accept_threshold_is_respected():
    results = [DetectionResult(module="presentation_attack", score=0.5, is_mock=True)]
    weights = {"presentation_attack": 1.0}
    assert fuse(results, weights=weights, accept_threshold=0.4).accepted is True
    assert fuse(results, weights=weights, accept_threshold=0.6).accepted is False


def test_empty_results_raises():
    with pytest.raises(ValueError):
        fuse([])


def test_per_module_scores_and_is_mock_are_reported():
    result = fuse(ALL_GENUINE)
    assert result.per_module_scores["replay"] == 1.0
    assert result.per_module_is_mock["replay"] is False
    assert result.per_module_is_mock["presentation_attack"] is True
