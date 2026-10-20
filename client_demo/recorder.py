"""Short liveness-clip recorder for the Live Capture tab.

The browser streams the camera to the Streamlit process over WebRTC
(streamlit-webrtc); `ClipRecorder.on_frame` is called from that stream's
worker thread for every frame. While a recording is active it keeps each
frame with its arrival time and draws a "REC" indicator plus the current
prompt onto the preview, so the person sees exactly what is being recorded
and when to perform the challenge. Thread-safe; no Streamlit calls in here.
"""
from __future__ import annotations

import threading
import time

import numpy as np

RECORD_SECONDS = 4.0
LOOK_STRAIGHT_SECONDS = 1.2  # first part of the clip: frontal frame for the detectors
MAX_FRAMES_SENT = 8


class ClipRecorder:
    def __init__(self):
        self._lock = threading.Lock()
        self._frames: list[tuple[float, np.ndarray]] = []
        self._start = 0.0
        self._until = 0.0
        self._challenge = ""

    def start(self, challenge: str, seconds: float = RECORD_SECONDS, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._frames = []
            self._start, self._until, self._challenge = now, now + seconds, challenge

    def is_recording(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            return self._start <= now < self._until

    def on_frame(self, frame: np.ndarray, now: float | None = None) -> np.ndarray:
        """Record `frame` (RGB) if a recording is active; return the preview
        frame with the recording overlay drawn on a copy."""
        now = time.time() if now is None else now
        with self._lock:
            recording = self._start <= now < self._until
            if recording:
                self._frames.append((now, frame))
            elapsed, remaining, challenge = now - self._start, self._until - now, self._challenge
        if not recording:
            return frame
        prompt = "Look straight at the camera" if elapsed < LOOK_STRAIGHT_SECONDS else f"Now: {challenge}"
        return _draw_overlay(frame, prompt, remaining)

    def take(self) -> tuple[list[np.ndarray], list[float]]:
        """All frames recorded so far and their arrival timestamps."""
        with self._lock:
            frames = list(self._frames)
        return [f for _, f in frames], [t for t, _ in frames]


def sample_frames(frames: list[np.ndarray], n: int = MAX_FRAMES_SENT) -> list[np.ndarray]:
    """Evenly spaced subset, always keeping the first (frontal) and last frame.
    The full timestamp list is still sent, for the injection timing check."""
    if len(frames) <= n:
        return list(frames)
    idx = np.linspace(0, len(frames) - 1, n).round().astype(int)
    return [frames[i] for i in idx]


def _draw_overlay(frame: np.ndarray, prompt: str, remaining: float) -> np.ndarray:
    import cv2

    out = np.ascontiguousarray(frame).copy()
    h, w = out.shape[:2]
    cv2.rectangle(out, (0, 0), (w, 44), (0, 0, 0), thickness=-1)
    cv2.circle(out, (22, 22), 9, (230, 30, 30), thickness=-1)
    cv2.putText(out, f"REC  {max(remaining, 0):.1f}s", (40, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2, cv2.LINE_AA)
    cv2.putText(out, prompt, (170, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.65, (255, 220, 120), 2, cv2.LINE_AA)
    cv2.rectangle(out, (0, 0), (w - 1, h - 1), (230, 30, 30), thickness=4)
    return out
