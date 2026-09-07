"""Face Morphing Detection - spec Section 6.2.

Spec explicitly allows a non-ML approach here ("feature-based morphing
artifact detection ... or landmark-symmetry deviation model"), so unlike
presentation_attack.py / deepfake_detector.py this module has a genuine
working implementation rather than a stub-plus-mock:

- If MediaPipe Face Mesh is importable, use real facial landmarks to measure
  left/right symmetry deviation around the eyes/mouth/jaw - morphing two
  identities together tends to blend landmark positions asymmetrically and
  softens edges around the blend seams.
- Otherwise, fall back to a pixel-domain proxy: mirror the face crop
  left-right and measure the residual difference directly. Weaker (no
  landmark alignment) but needs zero extra dependencies.

Both paths are legitimate signal-processing methods, not a trained
classifier, so there is no separate "pretrained" checkpoint to download for
this module - `mode` only controls whether MediaPipe is *allowed*, not
whether a model file is loaded.
"""
from __future__ import annotations

import logging

import numpy as np
from PIL import Image

from detection.base import DetectionResult, clip01

logger = logging.getLogger(__name__)


class MorphDetector:
    module_name = "morph"

    def __init__(self, mode: str = "pretrained", device: str = "cpu"):
        # `mode="mock"` forces the pixel-mirror fallback even if MediaPipe is
        # installed, mainly so tests/evaluation can compare both paths.
        self.device = device
        self.mode = mode
        self._face_mesh = None
        if mode != "mock":
            self._face_mesh = self._try_load_mediapipe()

    def _try_load_mediapipe(self):
        try:
            import mediapipe as mp

            return mp.solutions.face_mesh.FaceMesh(static_image_mode=True, max_num_faces=1, refine_landmarks=True)
        except Exception as exc:
            logger.warning("Morph: MediaPipe unavailable (%s); using pixel-mirror symmetry fallback.", exc)
            return None

    def predict(self, frame: np.ndarray) -> DetectionResult:
        if self._face_mesh is not None:
            result = self._predict_landmarks(frame)
            if result is not None:
                return result
        return self._predict_pixel_mirror(frame)

    def _predict_landmarks(self, frame: np.ndarray) -> DetectionResult | None:
        results = self._face_mesh.process(frame)
        if not results.multi_face_landmarks:
            return None

        landmarks = results.multi_face_landmarks[0].landmark
        h, w = frame.shape[:2]
        pts = np.array([(lm.x * w, lm.y * h) for lm in landmarks])

        # Symmetric landmark index pairs across the vertical face midline
        # (MediaPipe's 468-point topology): eye corners, mouth corners, jaw.
        symmetric_pairs = [(33, 263), (61, 291), (176, 400), (105, 334), (159, 386)]
        center_x = pts[:, 0].mean()

        deviations = []
        for left_idx, right_idx in symmetric_pairs:
            if left_idx >= len(pts) or right_idx >= len(pts):
                continue
            left_mirrored_x = 2 * center_x - pts[left_idx, 0]
            dx = abs(left_mirrored_x - pts[right_idx, 0])
            dy = abs(pts[left_idx, 1] - pts[right_idx, 1])
            deviations.append(np.hypot(dx, dy))

        if not deviations:
            return None

        mean_deviation = float(np.mean(deviations))
        face_width = float(pts[:, 0].max() - pts[:, 0].min()) or 1.0
        normalized_deviation = mean_deviation / face_width

        # Higher deviation => more likely morphed/blended => lower "genuine" score.
        score = clip01(1.0 - normalized_deviation / 0.08)

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=False,
            details={"mean_landmark_deviation_px": mean_deviation, "normalized_deviation": normalized_deviation},
        )

    def _predict_pixel_mirror(self, frame: np.ndarray) -> DetectionResult:
        img = Image.fromarray(frame).convert("L").resize((128, 128))
        arr = np.asarray(img, dtype=np.float64)
        mirrored = arr[:, ::-1]
        residual = np.abs(arr - mirrored)
        asymmetry = float(residual.mean())

        # Normalize: real faces are naturally somewhat asymmetric; morphs
        # tend to show either unusually smooth blending (low asymmetry with
        # low local variance) or ghosting artifacts (localized high-residual
        # patches). This proxy uses overall asymmetry as a weak signal only.
        score = clip01(1.0 - abs(asymmetry - 18.0) / 30.0)

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=True,
            details={"pixel_mirror_asymmetry": asymmetry},
        )
