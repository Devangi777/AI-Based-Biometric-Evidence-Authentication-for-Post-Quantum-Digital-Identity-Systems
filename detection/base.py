"""Shared types for the AI attack-detection pipeline (spec Section 6).

Every module's score convention: 0.0 = certainly an attack, 1.0 = certainly
bona-fide/genuine, so `.env`'s per-module thresholds ("score >= threshold =>
genuine") and detection/fusion.py's weighted average both operate on a
consistent scale.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


@dataclass
class DetectionResult:
    module: str
    score: float  # 0..1, higher = more likely genuine/bona-fide
    is_mock: bool
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.score = clip01(self.score)


class MockModeWarning(UserWarning):
    """Raised as a log warning (not an exception) whenever a detector falls
    back to its mock heuristic instead of a real pretrained model - kept as
    a named class so tests/log filters can key on it if needed."""
