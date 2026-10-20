"""Face-region cropping shared by the detectors that should look at the face
rather than the whole frame (presentation_attack.py, morph_detector.py).

Uses MediaPipe Face Mesh when it is importable and allowed; otherwise (or if
no face is found) falls back to the central region of the frame. Each
detector owns its own FaceRegionFinder because a Face Mesh instance is not
safe to share across threads.
"""
from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger(__name__)

_SYMMETRIC_PAIRS = [(33, 263), (61, 291), (176, 400), (105, 334), (159, 386)]


class FaceRegionFinder:
    def __init__(self, use_mediapipe: bool = True, margin: float = 0.2, owner: str = "detector"):
        self.margin = margin
        self._face_mesh = None
        if use_mediapipe:
            try:
                import mediapipe as mp

                self._face_mesh = mp.solutions.face_mesh.FaceMesh(
                    static_image_mode=True, max_num_faces=1, refine_landmarks=True
                )
            except Exception as exc:
                logger.warning("%s: MediaPipe unavailable (%s); analysing the central crop instead of the face box.", owner, exc)

    @property
    def available(self) -> bool:
        return self._face_mesh is not None

    def crop(self, frame: np.ndarray) -> tuple[np.ndarray, dict]:
        """Return (region, details); details["face_crop"] is "landmarks" or "center"."""
        h, w = frame.shape[:2]
        if self._face_mesh is not None:
            results = self._face_mesh.process(np.ascontiguousarray(frame[..., :3]))
            if results.multi_face_landmarks:
                landmarks = results.multi_face_landmarks[0].landmark
                pts = np.array([(lm.x * w, lm.y * h) for lm in landmarks])
                (x0, y0), (x1, y1) = pts.min(axis=0), pts.max(axis=0)
                mx, my = self.margin * (x1 - x0), self.margin * (y1 - y0)
                x0, y0 = int(max(0, x0 - mx)), int(max(0, y0 - my))
                x1, y1 = int(min(w, x1 + mx)), int(min(h, y1 + my))
                if x1 - x0 >= 32 and y1 - y0 >= 32:
                    return frame[y0:y1, x0:x1], {"face_crop": "landmarks", **_landmark_asymmetry(pts)}
        return frame[int(0.2 * h): int(0.8 * h), int(0.2 * w): int(0.8 * w)], {"face_crop": "center"}


def _landmark_asymmetry(pts: np.ndarray) -> dict:
    center_x = pts[:, 0].mean()
    deviations = [
        np.hypot(abs(2 * center_x - pts[left, 0] - pts[right, 0]), abs(pts[left, 1] - pts[right, 1]))
        for left, right in _SYMMETRIC_PAIRS
    ]
    face_width = float(pts[:, 0].max() - pts[:, 0].min()) or 1.0
    return {"landmark_asymmetry": float(np.mean(deviations)) / face_width}
