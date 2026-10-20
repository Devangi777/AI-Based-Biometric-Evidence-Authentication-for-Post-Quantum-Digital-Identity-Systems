"""Injection Attack Detection - spec Section 6.5.

The spec is explicit that this is "the most research-y" module and should be
"documented clearly as a heuristic + ML hybrid rather than a fully solved
classifier" - that limitation is real, not a shortcoming of this
implementation, so it's stated here rather than hidden.

Two independent signals, combined:
1. Frame-timing consistency (heuristic, always active): a real camera feed
   has a fairly stable inter-frame interval; a virtual-camera/injected
   stream assembled from a pre-recorded file often shows telltale jitter or
   suspiciously exact regularity once re-encoded. Computed from
   `frame_timestamps` supplied by the caller (the actual capture pipeline,
   not something this module can observe on its own).
2. A lightweight CNN compression-artifact classifier (per spec: "detect
   virtual-camera/injected-stream artifacts"). Like presentation_attack.py
   and deepfake_detector.py, no checkpoint exists in this environment, so
   this always falls back to a lower-weighted heuristic proxy (block-edge
   energy from re-encoding/re-compression) rather than silently no-op'ing -
   see detection/README-models.md.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from PIL import Image

from detection.base import DetectionResult, clip01

logger = logging.getLogger(__name__)

WEIGHTS_PATH = Path(__file__).parent / "weights" / "injection_cnn.pth"

# Frame-interval jitter bands for a live camera feed. Jitter is a robust
# coefficient of variation (1.4826 * MAD / median interval), so a few late
# or dropped frames in an otherwise steady live stream don't dominate it.
_MIN_LIVE_JITTER = 0.002  # at or below: synthetic, exactly regular timestamps
_FULL_CREDIT_JITTER = 0.02
_MAX_LIVE_JITTER = 0.35  # above: increasingly erratic, reaching 0 at 1.0
_MIN_TIMING_INTERVALS = 8


class InjectionDetector:
    module_name = "injection"

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
            import torch  # noqa: F401

            if not WEIGHTS_PATH.exists():
                raise FileNotFoundError(f"{WEIGHTS_PATH} not found - see detection/README-models.md")
            raise FileNotFoundError("Injection CNN architecture is not vendored in this repo yet")
        except Exception as exc:
            logger.warning("Injection: pretrained CNN unavailable (%s); using heuristic-only scoring.", exc)
            return None

    def predict(self, frame: np.ndarray, frame_timestamps: list[float] | None = None) -> DetectionResult:
        compression_score, compression_details = self._compression_artifact_heuristic(frame)
        timing_score, timing_details = self._frame_timing_heuristic(frame_timestamps)

        # Timing is the stronger, better-grounded signal when available;
        # compression-artifact proxy is weak on its own (see module docstring).
        if frame_timestamps:
            score = clip01(0.65 * timing_score + 0.35 * compression_score)
        else:
            score = compression_score

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=self._model is None,
            details={**compression_details, **timing_details},
        )

    def _compression_artifact_heuristic(self, frame: np.ndarray) -> tuple[float, dict]:
        """8x8 block-boundary energy: re-encoding a screen-recorded or
        virtual-camera stream through a second lossy codec tends to leave
        elevated gradient energy exactly at 8-pixel block boundaries
        (classic JPEG/MPEG block-artifact signature)."""
        gray = np.asarray(Image.fromarray(frame).convert("L"), dtype=np.float64)
        h, w = gray.shape

        col_diffs = np.abs(np.diff(gray, axis=1))
        row_diffs = np.abs(np.diff(gray, axis=0))

        block_cols = [c for c in range(7, w - 1, 8)]
        block_rows = [r for r in range(7, h - 1, 8)]

        block_col_energy = float(col_diffs[:, block_cols].mean()) if block_cols else 0.0
        block_row_energy = float(row_diffs[block_rows, :].mean()) if block_rows else 0.0
        overall_col_energy = float(col_diffs.mean()) if col_diffs.size else 1e-6
        overall_row_energy = float(row_diffs.mean()) if row_diffs.size else 1e-6

        block_ratio = ((block_col_energy / (overall_col_energy or 1e-6)) + (block_row_energy / (overall_row_energy or 1e-6))) / 2

        # block_ratio near 1.0 = no unusual block structure (genuine);
        # elevated ratio = re-encoding artifact (injected/replayed stream).
        score = clip01(1.0 - (block_ratio - 1.1) / 1.5)
        return score, {"block_boundary_energy_ratio": block_ratio}

    def _frame_timing_heuristic(self, frame_timestamps: list[float] | None) -> tuple[float, dict]:
        # With only a handful of intervals, live jitter can read as "machine-
        # perfect" by chance (~2% of 4-interval live sequences did), so
        # timing is only judged on longer sequences. Live recordings send
        # every frame's timestamp (~100+); video files send all of theirs.
        if not frame_timestamps or len(frame_timestamps) < _MIN_TIMING_INTERVALS + 1:
            return 1.0, {"timing_checked": False}

        intervals = np.diff(frame_timestamps)
        median = float(np.median(intervals))
        if median <= 0:
            return 1.0, {"timing_checked": False}

        jitter_ratio = float(1.4826 * np.median(np.abs(intervals - median)) / median)

        # Real camera capture has some scheduling jitter (typically a few
        # percent of the frame interval). Both ends are penalized:
        #  - near-zero jitter: timestamps synthesized from a container's
        #    nominal fps (a pre-recorded file or virtual camera) are exact.
        #    The previous symmetric curve still gave jitter 0 a score of
        #    0.75, so injected streams passed; this ramp gives it 0.
        #  - very high jitter: dropped/duplicated frames from a virtual camera.
        low_side = (jitter_ratio - _MIN_LIVE_JITTER) / (_FULL_CREDIT_JITTER - _MIN_LIVE_JITTER)
        high_side = 1.0 - (jitter_ratio - _MAX_LIVE_JITTER) / (1.0 - _MAX_LIVE_JITTER)
        score = clip01(min(low_side, high_side))
        return score, {"timing_checked": True, "frame_interval_jitter_ratio": jitter_ratio}
