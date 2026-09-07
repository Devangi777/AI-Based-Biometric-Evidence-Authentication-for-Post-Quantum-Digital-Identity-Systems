"""Unit tests for evaluation/metrics.py's classification metrics."""
from __future__ import annotations

import pytest

from evaluation.metrics import evaluate


def test_perfect_classifier():
    scores = [0.9, 0.8, 0.1, 0.2]
    labels = [True, True, False, False]
    m = evaluate(scores, labels, threshold=0.5)
    assert m.accuracy == 1.0
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.apcer == 0.0
    assert m.bpcer == 0.0
    assert m.n_genuine == 2
    assert m.n_attack == 2


def test_all_attacks_misclassified_as_genuine_is_apcer_1():
    scores = [0.9, 0.9, 0.9, 0.9]  # everything predicted genuine
    labels = [True, True, False, False]
    m = evaluate(scores, labels, threshold=0.5)
    assert m.apcer == 1.0  # both attacks wrongly accepted
    assert m.bpcer == 0.0  # both genuine correctly accepted


def test_all_genuine_misclassified_as_attack_is_bpcer_1():
    scores = [0.1, 0.1, 0.1, 0.1]  # everything predicted attack
    labels = [True, True, False, False]
    m = evaluate(scores, labels, threshold=0.5)
    assert m.bpcer == 1.0  # both genuine wrongly rejected
    assert m.apcer == 0.0  # both attacks correctly rejected


def test_threshold_shifts_predictions():
    scores = [0.6, 0.4]
    labels = [True, False]
    strict = evaluate(scores, labels, threshold=0.5)
    assert strict.accuracy == 1.0

    lax = evaluate(scores, labels, threshold=0.9)  # both now predicted "attack"
    assert lax.apcer == 0.0
    assert lax.bpcer == 1.0


def test_mismatched_lengths_raises():
    with pytest.raises(ValueError):
        evaluate([0.5], [True, False])


def test_empty_input_raises():
    with pytest.raises(ValueError):
        evaluate([], [])


def test_as_dict_contains_all_fields():
    m = evaluate([0.9], [True])
    d = m.as_dict()
    assert set(d.keys()) == {
        "accuracy", "precision", "recall", "f1", "apcer", "bpcer", "n_genuine", "n_attack", "threshold",
    }
