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

Mock-mode heuristic: three classic recapture cues, measured on the face
region (MediaPipe box, or the central crop without MediaPipe):

- Black level (weight 0.5): the darkest 1% of face-region pixels. A live
  face always has true blacks (pupils, nostrils, hair); paper and screens
  cannot reproduce them, because of ink/backlight reflectance and glare.
  Live webcam frames measured 0-2; recaptured prints/screens 50-62.
- Sharpness (0.3): Laplacian variance at a fixed 160 px face width. Prints
  lose detail and a phone/photo held close to a fixed-focus webcam is out
  of focus. Live webcam faces measured 26-109; a printed photo 7.
- Saturation (0.2): mean HSV saturation of the face. Recaptures look
  washed out. Kept low-weight because it also varies with skin tone and
  lighting.

A previous version scored whole-frame sharpness / 500, a scale only a sharp
still photo reaches; real webcam frames (15-50) were all rejected.
This is still a much weaker signal than a trained PAD model.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from PIL import Image

from detection.base import DetectionResult, clip01
from detection.face_region import FaceRegionFinder

logger = logging.getLogger(__name__)

WEIGHTS_PATH = Path(__file__).parent / "weights" / "pad_minifasnet.pth"

_FACE_WIDTH = 160  # face region is resized to this width before measuring sharpness
# (attack-like, live-like) ramps for each cue
_BLACK_LEVEL_RAMP = (40.0, 15.0)  # 1st-percentile face luminance, 0-255
_SHARPNESS_RAMP = (np.log10(8.0), np.log10(25.0))  # log10 Laplacian variance
_SATURATION_RAMP = (45.0, 75.0)  # mean HSV saturation, 0-255
_WEIGHTS = {"black_level": 0.5, "sharpness": 0.3, "saturation": 0.2}


def _ramp(x: float, attack_live: tuple[float, float]) -> float:
    attack, live = attack_live
    return clip01((x - attack) / (live - attack))


class PresentationAttackDetector:
    module_name = "presentation_attack"

    def __init__(self, mode: str = "pretrained", device: str = "cpu"):
        self.device = device
        self.mode = mode
        self._model = None
        # `mode="mock"` also skips MediaPipe face cropping (central crop only).
        self._faces = FaceRegionFinder(use_mediapipe=mode != "mock", owner="PAD")
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
        region, crop_details = self._faces.crop(np.asarray(Image.fromarray(frame).convert("RGB")))
        face = Image.fromarray(region)

        luminance = np.asarray(face.convert("L"), dtype=np.float64)
        black_level = float(np.percentile(luminance, 1))

        height = max(8, round(face.height * _FACE_WIDTH / face.width))
        gray = np.asarray(face.convert("L").resize((_FACE_WIDTH, height), Image.BILINEAR), dtype=np.float64)
        # Manual 3x3 Laplacian (no OpenCV/scipy dependency in the mock path).
        lap = -4 * gray[1:-1, 1:-1] + gray[:-2, 1:-1] + gray[2:, 1:-1] + gray[1:-1, :-2] + gray[1:-1, 2:]
        sharpness = float(lap.var()) if lap.size else 0.0

        saturation = float(np.asarray(face.convert("HSV"), dtype=np.float64)[..., 1].mean())

        cues = {
            "black_level": _ramp(black_level, _BLACK_LEVEL_RAMP),
            "sharpness": _ramp(np.log10(max(sharpness, 1e-6)), _SHARPNESS_RAMP),
            "saturation": _ramp(saturation, _SATURATION_RAMP),
        }
        score = sum(_WEIGHTS[k] * v for k, v in cues.items())

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=True,
            details={
                "face_black_level": black_level,
                "face_sharpness": sharpness,
                "face_saturation": saturation,
                **crop_details,
            },
        )

    def _predict_pretrained(self, frame: np.ndarray) -> DetectionResult:  # pragma: no cover
        raise RuntimeError("Pretrained PAD path is not reachable without a loaded model")
