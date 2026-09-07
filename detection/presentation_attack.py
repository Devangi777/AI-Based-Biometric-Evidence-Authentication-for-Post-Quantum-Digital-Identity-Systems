"""Presentation Attack Detection (PAD) - spec Section 6.1.

Pretrained model (per spec): Silent-Face-Anti-Spoofing (MiniFASNet) -
lightweight, CPU-inference-friendly. See detection/README-models.md for the
exact checkpoint source and where to place it.

This environment cannot download that checkpoint (no internet dataset/model
downloads per the build instructions), and the MiniFASNet architecture
itself isn't vendored here (reproducing it incorrectly would silently give
meaningless scores, which is worse than being explicit about the gap). So
`mode="pretrained"` always logs a clear reason and falls back to
`mode="mock"` in this environment - this is the "documented fallback/mock
mode" the build instructions call for, not a permanent design choice.

Mock-mode heuristic: classic pre-deep-learning liveness proxies that need no
trained model - Laplacian-variance sharpness (screen/print recaptures are
typically softer than a live camera capture) and RGB channel diversity
(prints/screens often have a narrower color gamut). This is a much weaker
signal than a real trained PAD model; it exists purely so the pipeline is
exercisable end-to-end without downloads.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from PIL import Image

from detection.base import DetectionResult, clip01

logger = logging.getLogger(__name__)

WEIGHTS_PATH = Path(__file__).parent / "weights" / "pad_minifasnet.pth"


class PresentationAttackDetector:
    module_name = "presentation_attack"

    def __init__(self, mode: str = "pretrained", device: str = "cpu"):
        self.device = device
        self.mode = mode
        self._model = None
        if self.mode == "pretrained":
            self._model = self._try_load_model()
            if self._model is None:
                self.mode = "mock"

    def _try_load_model(self):
        try:
            import torch  # noqa: F401 - availability check

            if not WEIGHTS_PATH.exists():
                raise FileNotFoundError(f"{WEIGHTS_PATH} not found - see detection/README-models.md")
            raise FileNotFoundError(
                "MiniFASNet architecture is not vendored in this repo (only the checkpoint path is "
                "wired up) - see detection/README-models.md for what to add"
            )
        except Exception as exc:
            logger.warning("PAD: pretrained model unavailable (%s); using mock heuristic.", exc)
            return None

    def predict(self, frame: np.ndarray) -> DetectionResult:
        if self.mode == "mock" or self._model is None:
            return self._predict_mock(frame)
        return self._predict_pretrained(frame)  # pragma: no cover - unreachable until a model is wired in

    def _predict_mock(self, frame: np.ndarray) -> DetectionResult:
        gray = np.asarray(Image.fromarray(frame).convert("L"), dtype=np.float64)

        # Manual 3x3 Laplacian (avoids an OpenCV/scipy dependency for the
        # mock path - detection/README-models.md documents the real filters
        # a pretrained model would learn instead of this proxy).
        lap = -4 * gray[1:-1, 1:-1] + gray[:-2, 1:-1] + gray[2:, 1:-1] + gray[1:-1, :-2] + gray[1:-1, 2:]
        sharpness = float(lap.var()) if lap.size else 0.0

        rgb = np.asarray(frame, dtype=np.float64)
        channel_std = float(rgb.reshape(-1, rgb.shape[-1]).std(axis=0).mean()) if rgb.ndim == 3 else 0.0

        sharpness_score = clip01(sharpness / 500.0)
        color_score = clip01(channel_std / 60.0)
        score = clip01(0.6 * sharpness_score + 0.4 * color_score)

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=True,
            details={"sharpness": sharpness, "channel_std": channel_std},
        )

    def _predict_pretrained(self, frame: np.ndarray) -> DetectionResult:  # pragma: no cover
        raise RuntimeError("Pretrained PAD path is not reachable without a loaded model")
