"""Deepfake Detection - spec Section 6.3.

Pretrained model (per spec): Xception/EfficientNet-B4 on FaceForensics++, or
the lighter MesoNet/Meso4 if GPU time is limited. Meso4's architecture
(Afchar et al., 2018 - four conv+pool blocks, a small dense head) is simple
enough to define here directly in PyTorch, so `Meso4` below is a real,
correct-shape network definition - but with **no trained weights** (this
environment doesn't download FaceForensics++ or any checkpoint), running it
with random initialization would produce meaningless scores that look
plausible, which is worse than an honest mock. So `mode="pretrained"` only
actually runs Meso4 if a real checkpoint file is found at WEIGHTS_PATH;
otherwise it logs why and falls back to the mock heuristic below. See
detection/README-models.md for exactly what checkpoint to add.

Mock-mode heuristic: high-frequency energy ratio in the 2D FFT spectrum.
GAN/autoencoder-based face synthesis is documented in the deepfake-detection
literature (e.g. Frank et al. 2020, "Leveraging Frequency Analysis for Deep
Fake Image Recognition") to leave characteristic high-frequency artifacts
from upsampling operations. This is a real, if much weaker, signal-based
proxy - not a placeholder that returns a constant.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from PIL import Image

from detection.base import DetectionResult, clip01

logger = logging.getLogger(__name__)

WEIGHTS_PATH = Path(__file__).parent / "weights" / "deepfake_meso4.pth"


def _build_meso4():
    """Meso4 architecture (Afchar et al. 2018). Imports torch lazily so this
    module stays importable without torch installed (mock mode never calls
    this)."""
    import torch.nn as nn

    class Meso4(nn.Module):
        def __init__(self, num_classes: int = 2):
            super().__init__()
            self.conv1 = nn.Conv2d(3, 8, 3, padding=1)
            self.bn1 = nn.BatchNorm2d(8)
            self.conv2 = nn.Conv2d(8, 8, 5, padding=2)
            self.bn2 = nn.BatchNorm2d(8)
            self.conv3 = nn.Conv2d(8, 16, 5, padding=2)
            self.bn3 = nn.BatchNorm2d(16)
            self.conv4 = nn.Conv2d(16, 16, 5, padding=2)
            self.bn4 = nn.BatchNorm2d(16)
            self.pool = nn.MaxPool2d(2, 2)
            self.pool4 = nn.MaxPool2d(4, 4)
            self.leaky_relu = nn.LeakyReLU(0.1)
            self.dropout = nn.Dropout(0.5)
            self.fc1 = nn.Linear(16 * 8 * 8, 16)
            self.fc2 = nn.Linear(16, num_classes)

        def forward(self, x):
            x = self.pool(self.leaky_relu(self.bn1(self.conv1(x))))
            x = self.pool(self.leaky_relu(self.bn2(self.conv2(x))))
            x = self.pool(self.leaky_relu(self.bn3(self.conv3(x))))
            x = self.pool4(self.leaky_relu(self.bn4(self.conv4(x))))
            x = x.flatten(1)
            x = self.dropout(x)
            x = self.leaky_relu(self.fc1(x))
            x = self.dropout(x)
            return self.fc2(x)

    return Meso4()


class DeepfakeDetector:
    module_name = "deepfake"
    INPUT_SIZE = 256  # Meso4's native input resolution

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
            # Check for weights first: importing torch is slow, and pointless with no checkpoint.
            if not WEIGHTS_PATH.exists():
                raise FileNotFoundError(f"{WEIGHTS_PATH} not found - see detection/README-models.md")
            import torch
            model = _build_meso4()
            state_dict = torch.load(WEIGHTS_PATH, map_location=self.device)
            model.load_state_dict(state_dict)
            model.eval()
            return model
        except Exception as exc:
            logger.warning("Deepfake: pretrained Meso4 unavailable (%s); using mock FFT heuristic.", exc)
            return None

    def predict(self, frame: np.ndarray) -> DetectionResult:
        if self.mode == "mock" or self._model is None:
            return self._predict_mock(frame)
        return self._predict_pretrained(frame)

    def predict_video(self, frames: list[np.ndarray]) -> DetectionResult:
        """Aggregate per-frame scores across sampled frames (min, since a
        deepfake only needs to be detected in some frames to be caught)."""
        if not frames:
            raise ValueError("predict_video requires at least one frame")
        results = [self.predict(f) for f in frames]
        worst = min(results, key=lambda r: r.score)
        return DetectionResult(
            module=self.module_name,
            score=worst.score,
            is_mock=results[0].is_mock,
            details={**worst.details, "num_frames": len(results), "per_frame_scores": [r.score for r in results]},
        )

    def _predict_mock(self, frame: np.ndarray) -> DetectionResult:
        gray = np.asarray(Image.fromarray(frame).convert("L").resize((256, 256)), dtype=np.float64)
        spectrum = np.fft.fftshift(np.fft.fft2(gray))
        magnitude = np.abs(spectrum)

        h, w = magnitude.shape
        cy, cx = h // 2, w // 2
        radius = min(h, w) // 4
        yy, xx = np.ogrid[:h, :w]
        dist = np.hypot(yy - cy, xx - cx)

        low_freq_energy = float(magnitude[dist <= radius].sum())
        high_freq_energy = float(magnitude[dist > radius].sum())
        total = low_freq_energy + high_freq_energy or 1.0
        high_freq_ratio = high_freq_energy / total

        # Elevated high-frequency ratio => more likely a GAN upsampling
        # artifact => lower "genuine" score. Calibration is a rough proxy,
        # not fit to any labeled dataset - see module docstring.
        score = clip01(1.0 - (high_freq_ratio - 0.35) / 0.25)

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=True,
            details={"high_freq_ratio": high_freq_ratio},
        )

    def _predict_pretrained(self, frame: np.ndarray) -> DetectionResult:
        import torch

        img = Image.fromarray(frame).convert("RGB").resize((self.INPUT_SIZE, self.INPUT_SIZE))
        arr = np.asarray(img, dtype=np.float32) / 255.0
        tensor = torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0).to(self.device)

        with torch.no_grad():
            logits = self._model(tensor)
            probs = torch.softmax(logits, dim=1).squeeze(0)
            genuine_score = float(probs[0])  # class 0 == real, class 1 == fake, per training convention

        return DetectionResult(module=self.module_name, score=genuine_score, is_mock=False, details={})
