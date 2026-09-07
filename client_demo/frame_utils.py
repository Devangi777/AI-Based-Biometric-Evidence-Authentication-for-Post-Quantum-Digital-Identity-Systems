"""Frame encoding/decoding helpers for the Streamlit demo.

Keeps image/video handling out of streamlit_app.py so it's independently
testable without a Streamlit runtime.
"""
from __future__ import annotations

import base64
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image

IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png"}
VIDEO_SUFFIXES = {".mp4", ".mov"}


def frame_to_png_bytes(frame: np.ndarray) -> bytes:
    buf = BytesIO()
    Image.fromarray(frame).convert("RGB").save(buf, format="PNG")
    return buf.getvalue()


def frame_to_b64(frame: np.ndarray) -> str:
    return base64.b64encode(frame_to_png_bytes(frame)).decode("ascii")


def load_image_frames(path: Path) -> tuple[list[np.ndarray], None]:
    img = Image.open(path).convert("RGB")
    return [np.array(img)], None


def load_video_frames(path: Path, max_frames: int = 8) -> tuple[list[np.ndarray], list[float]]:
    """Uniformly samples up to `max_frames` frames from the video, returning
    each frame's approximate capture timestamp (seconds) for the injection
    detector's frame-timing heuristic."""
    import cv2

    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise ValueError(f"Could not open video file: {path}")

    fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or max_frames
    step = max(1, total // max_frames)

    frames: list[np.ndarray] = []
    timestamps: list[float] = []
    idx = 0
    try:
        while len(frames) < max_frames:
            ok, bgr = cap.read()
            if not ok:
                break
            if idx % step == 0:
                rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
                frames.append(rgb)
                timestamps.append(idx / fps)
            idx += 1
    finally:
        cap.release()

    if not frames:
        raise ValueError(f"No frames could be read from video file: {path}")
    return frames, timestamps


def load_attack_file(path: Path, max_frames: int = 8) -> tuple[list[np.ndarray], list[float] | None]:
    suffix = path.suffix.lower()
    if suffix in IMAGE_SUFFIXES:
        return load_image_frames(path)
    if suffix in VIDEO_SUFFIXES:
        return load_video_frames(path, max_frames=max_frames)
    raise ValueError(f"Unsupported attack sample file type {suffix!r} (expected one of {IMAGE_SUFFIXES | VIDEO_SUFFIXES})")
