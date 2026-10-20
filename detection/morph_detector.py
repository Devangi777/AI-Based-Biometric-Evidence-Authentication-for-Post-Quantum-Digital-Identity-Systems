"""Face Morphing Detection - spec Section 6.2.

Spec explicitly allows a non-ML approach here ("feature-based morphing
artifact detection"), so this module is a working signal-processing detector
rather than a stub-plus-mock. A morph is made by pixel-averaging two
identities, which leaves two artifacts in the fine detail (high-pass
residual) of the face region that a single live capture does not have:

- Ghosting: if the two source faces are not perfectly aligned, every edge
  appears twice at a fixed (dy, dx) offset, which shows up as a sharp
  secondary peak in the 2-D autocorrelation of the high-pass image. Genuine
  detail only has smooth, slowly decaying correlation (texture, blur), so
  the score uses peak *prominence* over its 2-pixel neighbourhood.
- Artificial symmetry: morphing tools align both faces to a common mean
  shape, and blending a face with a mirrored second identity makes skin
  texture, hair and noise left/right symmetric. Real faces are only
  symmetric in coarse structure, not in fine detail.

Measured on a public-domain portrait (genuine, JPEG/noise/blur variants) vs.
50/50 blends: ghost prominence <= 0.10 genuine vs. 0.22-0.37 for blends
misaligned by 2-4% of face width; mirror correlation ~0.03 genuine vs. ~0.99
for blends with a mirrored identity.

MediaPipe Face Mesh (if importable and `mode != "mock"`) is only used to
crop the face region and to report landmark asymmetry as a diagnostic;
without it the central region of the frame is analysed. Landmark symmetry
is not scored: it measured 0.03-0.045 face widths for both genuine faces and
morphs, so it cannot discriminate.
"""
from __future__ import annotations

import numpy as np
from PIL import Image, ImageFilter

from detection.base import DetectionResult, clip01
from detection.face_region import FaceRegionFinder


_ANALYSIS_WIDTH = 256  # larger face regions are downscaled to this; smaller ones are never upscaled
# Ghost offsets searched (radius, as a fraction of the analysed width).
# Below ~4% the correlation is ordinary optical blur, not a second face.
_GHOST_RADIUS = (0.04, 0.15)
# (no-evidence, full-evidence) ramps for each artifact
_GHOST_RAMP = (0.13, 0.22)
_MIRROR_RAMP = (0.20, 0.50)


def _ghost_prominence(detail: np.ndarray) -> float:
    """Largest sharp secondary peak in the normalized 2-D autocorrelation of
    `detail`, searched over offsets whose radius lies in _GHOST_RADIUS."""
    h, w = detail.shape
    shape = (2 * h, 2 * w)  # zero-pad: linear, not circular, correlation
    corr = np.real(np.fft.ifft2(np.abs(np.fft.fft2(detail, s=shape)) ** 2))
    overlap = np.real(np.fft.ifft2(np.abs(np.fft.fft2(np.ones_like(detail), s=shape)) ** 2))
    corr = np.fft.fftshift(corr / np.maximum(overlap, 1.0))
    neighbourhood = (np.roll(corr, 2, 0) + np.roll(corr, -2, 0) + np.roll(corr, 2, 1) + np.roll(corr, -2, 1)) / 4
    prominence = corr - neighbourhood
    yy, xx = np.indices(corr.shape)
    radius = np.hypot(yy - h, xx - w)
    ring = (radius >= max(4.0, _GHOST_RADIUS[0] * w)) & (radius <= _GHOST_RADIUS[1] * w)
    return float(prominence[ring].max()) if ring.any() else 0.0


def _ramp(x: float, lo_hi: tuple[float, float]) -> float:
    lo, hi = lo_hi
    return clip01((x - lo) / (hi - lo))


class MorphDetector:
    module_name = "morph"

    def __init__(self, mode: str = "pretrained", device: str = "cpu"):
        # `mode="mock"` disables MediaPipe face cropping (central crop only),
        # mainly so tests/evaluation run without the mediapipe dependency.
        self.device = device
        self.mode = mode
        self._faces = FaceRegionFinder(use_mediapipe=mode != "mock", owner="Morph")

    def predict(self, frame: np.ndarray) -> DetectionResult:
        region, crop_details = self._faces.crop(frame)
        ghost, mirror = self._artifact_correlations(region)
        score = 1.0 - max(_ramp(ghost, _GHOST_RAMP), _ramp(mirror, _MIRROR_RAMP))
        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=not self._faces.available,
            details={"ghost_prominence": ghost, "mirror_correlation": mirror, **crop_details},
        )

    @staticmethod
    def _artifact_correlations(region: np.ndarray) -> tuple[float, float]:
        gray = Image.fromarray(region).convert("L")
        if gray.width > _ANALYSIS_WIDTH:
            # Only ever downscale: upscaling a small face box interpolates
            # neighbouring pixels together, which reads as false "ghosting".
            gray = gray.resize((_ANALYSIS_WIDTH, max(32, round(gray.height * _ANALYSIS_WIDTH / gray.width))), Image.BILINEAR)
        g = np.asarray(gray, dtype=np.float64)
        detail = g - np.asarray(gray.filter(ImageFilter.GaussianBlur(2)), dtype=np.float64)
        detail = detail[8:-8, 8:-8]  # drop blur edge effects
        detail = (detail - detail.mean()) / (detail.std() + 1e-9)

        ghost = _ghost_prominence(detail)
        mirror = float((detail * detail[:, ::-1]).mean())
        return ghost, mirror
