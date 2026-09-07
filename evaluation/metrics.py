"""Section 8 evaluation metrics: standard classification metrics plus the
ISO/IEC 30107-3 PAD metrics APCER/BPCER, computed from (score, label) pairs.

Score convention matches detection/base.py: higher = more likely
bona-fide/genuine. `label=True` means the sample actually is bona-fide;
`label=False` means it's an attack.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ClassificationMetrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    apcer: float  # fraction of ATTACK samples wrongly classified as genuine (false accepts)
    bpcer: float  # fraction of GENUINE samples wrongly classified as attack (false rejects)
    n_genuine: int
    n_attack: int
    threshold: float

    def as_dict(self) -> dict:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "apcer": self.apcer,
            "bpcer": self.bpcer,
            "n_genuine": self.n_genuine,
            "n_attack": self.n_attack,
            "threshold": self.threshold,
        }


def evaluate(scores: list[float], labels: list[bool], threshold: float = 0.5) -> ClassificationMetrics:
    if len(scores) != len(labels):
        raise ValueError("scores and labels must be the same length")
    if not scores:
        raise ValueError("evaluate() requires at least one (score, label) sample")

    predictions = [s >= threshold for s in scores]  # True = predicted genuine

    tp = sum(1 for p, y in zip(predictions, labels) if p and y)
    tn = sum(1 for p, y in zip(predictions, labels) if not p and not y)
    fp = sum(1 for p, y in zip(predictions, labels) if p and not y)  # predicted genuine, actually attack
    fn = sum(1 for p, y in zip(predictions, labels) if not p and y)  # predicted attack, actually genuine

    n = len(labels)
    n_genuine = sum(1 for y in labels if y)
    n_attack = n - n_genuine

    accuracy = (tp + tn) / n
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    apcer = fp / n_attack if n_attack else 0.0
    bpcer = fn / n_genuine if n_genuine else 0.0

    return ClassificationMetrics(
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        apcer=apcer,
        bpcer=bpcer,
        n_genuine=n_genuine,
        n_attack=n_attack,
        threshold=threshold,
    )
