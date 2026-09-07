"""Replay Attack Detection - spec Section 6.4.

NOT a classifier: replay attacks resubmit genuine data, so a content
classifier structurally can't tell a replayed genuine sample from a fresh
one - only a freshness/matching check against previously-seen evidence can
(this is the same reason binding/session_binding.py's nonce mechanism
exists; this module is the content-hash-level complement to it, matching
even across different sessions/nonces if the exact same media is resent).

Design: maintain a perceptual hash (pHash) store of recently submitted
evidence; reject a new submission whose pHash is within a small Hamming
distance of a prior one inside REPLAY_HASH_WINDOW_SECONDS.
"""
from __future__ import annotations

import threading
import time

import imagehash
import numpy as np
from PIL import Image

from detection.base import DetectionResult

DEFAULT_HAMMING_THRESHOLD = 8  # imagehash pHash is a 64-bit hash by default
DEFAULT_WINDOW_SECONDS = 86400


class ReplayDetector:
    module_name = "replay"

    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS, hamming_threshold: int = DEFAULT_HAMMING_THRESHOLD):
        self.window_seconds = window_seconds
        self.hamming_threshold = hamming_threshold
        self._store: list[tuple[imagehash.ImageHash, float, str]] = []  # (hash, seen_at, session_id)
        self._lock = threading.Lock()

    def _prune_expired(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self._store = [(h, t, sid) for (h, t, sid) in self._store if t >= cutoff]

    def check_and_record(self, frame: np.ndarray, session_id: str) -> DetectionResult:
        """Check `frame` against the recent-evidence store, then record it
        regardless of outcome (so the *next* submission can detect this one
        being replayed too)."""
        img_hash = imagehash.phash(Image.fromarray(frame).convert("RGB"))
        now = time.time()

        with self._lock:
            self._prune_expired(now)

            best_match_distance = None
            best_match_session = None
            for stored_hash, seen_at, stored_session_id in self._store:
                distance = img_hash - stored_hash
                if best_match_distance is None or distance < best_match_distance:
                    best_match_distance = distance
                    best_match_session = stored_session_id

            self._store.append((img_hash, now, session_id))

        is_replay = best_match_distance is not None and best_match_distance <= self.hamming_threshold

        if is_replay:
            score = 0.0
        elif best_match_distance is None:
            score = 1.0
        else:
            # Smoothly interpolate confidence between the threshold and a
            # "clearly different" distance of 32 bits (half the hash length).
            score = min(1.0, (best_match_distance - self.hamming_threshold) / (32 - self.hamming_threshold))

        return DetectionResult(
            module=self.module_name,
            score=score,
            is_mock=False,
            details={
                "phash": str(img_hash),
                "best_match_hamming_distance": best_match_distance,
                "matched_session_id": best_match_session if is_replay else None,
                "store_size": len(self._store),
            },
        )

    def clear(self) -> None:
        """Used by tests/evaluation to reset state between runs."""
        with self._lock:
            self._store.clear()


# Process-wide singleton so replay detection works across sessions, matching
# the spec's "recently submitted biometric evidence" (not per-session) scope.
store = ReplayDetector(window_seconds=DEFAULT_WINDOW_SECONDS)
