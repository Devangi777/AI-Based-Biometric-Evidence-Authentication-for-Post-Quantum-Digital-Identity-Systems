"""Unit tests for detection/liveness_challenge.py (spec Section 7 step 6d's
AI-verified challenge fulfilment). No frames/MediaPipe needed for the
digit-challenge and fallback paths tested here.
"""
from __future__ import annotations

from detection.liveness_challenge import verify_challenge


def test_say_the_number_matches_correct_digits():
    assert verify_challenge("Say the number 4821", "4821") is True


def test_say_the_number_rejects_wrong_digits():
    assert verify_challenge("Say the number 4821", "9999") is False


def test_say_the_number_rejects_empty_response():
    assert verify_challenge("Say the number 4821", "") is False


def test_turn_head_without_frames_falls_back_to_nonempty_check():
    assert verify_challenge("Turn your head slightly left", "done") is True
    assert verify_challenge("Turn your head slightly left", "") is False


def test_nod_without_frames_falls_back_to_nonempty_check():
    assert verify_challenge("Nod your head once", "  ") is False
    assert verify_challenge("Nod your head once", "ok") is True


def test_unrecognized_challenge_falls_back_to_nonempty_check():
    assert verify_challenge("some future challenge type", "anything") is True
    assert verify_challenge("some future challenge type", "") is False
