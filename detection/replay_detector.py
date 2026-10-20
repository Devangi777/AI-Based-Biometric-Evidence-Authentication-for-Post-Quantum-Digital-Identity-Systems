"""Replay Attack Detection - spec Section 6.4.

NOT a classifier: replay attacks resubmit genuine data, so a content
classifier structurally can't tell a replayed genuine sample from a fresh
one - only a freshness/matching check against previously-seen evidence can
(this is the same reason binding/session_binding.py's nonce mechanism
exists; this module is the content-hash-level complement to it, matching
even across different sessions/nonces if the exact same media is resent).

Design: keep recently submitted evidence for REPLAY_HASH_WINDOW_SECONDS and
flag a new submission only if it is the *same capture*, which takes two
checks:

1. Perceptual hash (pHash) within a small Hamming distance - same picture
   structure, robust to re-encoding and resizing. Not sufficient alone: two
   genuine recordings of the same person sitting in the same spot also
   match on pHash, and were being rejected as replays.
2. The fine detail (high-pass residual of a native-resolution central crop)
   correlates with that earlier capture. A resent copy keeps it (measured
   0.92-1.00, including JPEG re-saves); a new recording has fresh sensor
   noise and is never pixel-aligned with the last one (1 px of movement
   already drops it to ~0.7, 2 px to <= 0.41).

A pHash match that fails check 2 is reported as "same scene, new capture"
and does not veto.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import imagehash
import numpy as np
from PIL import Image, ImageFilter

from detection.base import DetectionResult

DEFAULT_HAMMING_THRESHOLD = 8  # imagehash pHash is a 64-bit hash by default
DEFAULT_WINDOW_SECONDS = 86400
SAME_CAPTURE_CORRELATION = 0.85
_FINGERPRINT_SIZE = 256  # side of the native-resolution central crop
_MAX_STORE = 5000
_SAME_SCENE_SCORE = 0.75


@dataclass
class _Seen:
    phash: imagehash.ImageHash
    fingerprint: np.ndarray
    seen_at: float
    session_id: str


def _fingerprint(frame: np.ndarray) -> np.ndarray:
    gray = Image.fromarray(frame).convert("L")
    w, h = gray.size
    n = min(_FINGERPRINT_SIZE, w, h)
    gray = gray.crop(((w - n) // 2, (h - n) // 2, (w - n) // 2 + n, (h - n) // 2 + n))
    a = np.asarray(gray, dtype=np.float32)
    residual = a - np.asarray(gray.filter(ImageFilter.GaussianBlur(1.0)), dtype=np.float32)
    return ((residual - residual.mean()) / (residual.std() + 1e-6)).astype(np.float16)


def _correlation(a: np.ndarray, b: np.ndarray) -> float:
    n = min(a.shape[0], b.shape[0])
    a, b = a[:n, :n].astype(np.float32), b[:n, :n].astype(np.float32)
    return float((a * b).mean())


class ReplayDetector:
    module_name = "replay"

    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS, hamming_threshold: int = DEFAULT_HAMMING_THRESHOLD):
        self.window_seconds = window_seconds
        self.hamming_threshold = hamming_threshold
        self._store: list[_Seen] = []
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self._store = [s for s in self._store if s.seen_at >= cutoff][-_MAX_STORE:]

    def check_and_record(self, frame: np.ndarray, session_id: str) -> DetectionResult:
        """Check `frame` against the recent-evidence store, then record it
        regardless of outcome (so the *next* submission can detect this one
        being replayed too)."""
        img_hash = imagehash.phash(Image.fromarray(frame).convert("RGB"))
        fingerprint = _fingerprint(frame)
        now = time.time()

        with self._lock:
            self._prune(now)
            best_distance = best_correlation = replay_of = None
            for seen in self._store:
                distance = img_hash - seen.phash
                if best_distance is None or distance < best_distance:
                    best_distance = distance
                if distance > self.hamming_threshold:
                    continue
                correlation = _correlation(fingerprint, seen.fingerprint)
                if best_correlation is None or correlation > best_correlation:
                    best_correlation = correlation
                if correlation >= SAME_CAPTURE_CORRELATION and replay_of is None:
                    replay_of = seen
            self._store.append(_Seen(img_hash, fingerprint, now, session_id))
            store_size = len(self._store)

        hash_match = best_distance is not None and best_distance <= self.hamming_threshold
        is_replay = replay_of is not None

        if is_replay:
            score = 0.0
        elif hash_match:
            score = _SAME_SCENE_SCORE  # same scene, new capture: not a replay
        elif best_distance is None:
            score = 1.0
        else:
            # Non-matches always score >= 0.5 so that only a real replay can
            # trip the fusion engine's per-module veto (THRESHOLD_REPLAY=0.5);
            # confidence rises toward 1.0 at a "clearly different" 32 bits.
            closeness = (best_distance - self.hamming_threshold) / (32 - self.hamming_threshold)
            score = 0.5 + 0.5 * min(1.0, closeness)

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=False,
            details={
                "phash": str(img_hash),
                "best_match_hamming_distance": best_distance,
                "detail_correlation": best_correlation,
                "same_scene_new_capture": bool(hash_match and not is_replay),
                "matched_session_id": replay_of.session_id if is_replay else None,
                "store_size": store_size,
            },
        )

    def clear(self) -> None:
        """Used by tests/evaluation to reset state between runs."""
        with self._lock:
            self._store.clear()


# Process-wide singleton so replay detection works across sessions, matching
# the spec's "recently submitted biometric evidence" (not per-session) scope.
store = ReplayDetector(window_seconds=DEFAULT_WINDOW_SECONDS)
