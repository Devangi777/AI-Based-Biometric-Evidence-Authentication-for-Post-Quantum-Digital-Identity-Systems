"""Unit tests for the pure-Python parts of client_demo/ (frame encoding and
API-client helpers). streamlit_app.py itself is UI glue and was smoke-tested
manually by running `streamlit run client_demo/streamlit_app.py` and
confirming it serves without a traceback (see the Stage 7 commit message) -
not something worth an automated test here given it needs a live server,
webcam, and browser to exercise meaningfully.
"""
from __future__ import annotations

import numpy as np
import pytest
from PIL import Image

from client_demo.api_client import now_iso, sha256_hex
from client_demo.frame_utils import frame_to_b64, frame_to_png_bytes, load_attack_file, load_image_frames


def test_sha256_hex_matches_hashlib():
    import hashlib

    data = b"some evidence bytes"
    assert sha256_hex(data) == hashlib.sha256(data).hexdigest()


def test_now_iso_is_parseable():
    from datetime import datetime

    ts = now_iso()
    parsed = datetime.fromisoformat(ts)
    assert parsed.tzinfo is not None


def test_frame_to_png_bytes_round_trips_via_pil():
    from io import BytesIO

    frame = np.random.default_rng(0).integers(0, 256, size=(32, 32, 3), dtype=np.uint8)
    png_bytes = frame_to_png_bytes(frame)
    decoded = np.array(Image.open(BytesIO(png_bytes)).convert("RGB"))
    assert decoded.shape == frame.shape
    assert np.array_equal(decoded, frame)


def test_frame_to_b64_is_base64_of_png_bytes():
    import base64

    frame = np.zeros((8, 8, 3), dtype=np.uint8)
    assert frame_to_b64(frame) == base64.b64encode(frame_to_png_bytes(frame)).decode("ascii")


def test_load_image_frames_returns_single_frame(tmp_path):
    frame = np.random.default_rng(1).integers(0, 256, size=(16, 16, 3), dtype=np.uint8)
    path = tmp_path / "sample.jpg"
    Image.fromarray(frame).save(path)

    frames, timestamps = load_image_frames(path)
    assert len(frames) == 1
    assert frames[0].shape == (16, 16, 3)
    assert timestamps is None


def test_load_attack_file_dispatches_by_suffix(tmp_path):
    frame = np.zeros((8, 8, 3), dtype=np.uint8)
    jpg_path = tmp_path / "a.jpg"
    Image.fromarray(frame).save(jpg_path)
    frames, timestamps = load_attack_file(jpg_path)
    assert len(frames) == 1

    with pytest.raises(ValueError):
        load_attack_file(tmp_path / "unsupported.txt")


def test_quality_check_rejects_dark_and_blurry_frames():
    from client_demo.frame_utils import quality_check

    rng = np.random.default_rng(2)
    textured = rng.integers(40, 220, size=(240, 320, 3), dtype=np.uint8)
    assert quality_check(textured) == (True, "ok")
    assert quality_check(np.full((240, 320, 3), 10, dtype=np.uint8))[0] is False  # too dark
    assert quality_check(np.full((240, 320, 3), 128, dtype=np.uint8))[0] is False  # no detail at all


def test_challenge_answer_matches_liveness_verifier():
    from client_demo.api_client import challenge_answer
    from detection.liveness_challenge import verify_challenge

    for challenge in ("Say the number 4821", "Turn your head slightly left", "Nod your head once"):
        assert verify_challenge(challenge, challenge_answer(challenge))
    assert not verify_challenge("Say the number 4821", "1234")


def test_clip_recorder_records_only_inside_its_window_and_overlays_preview():
    from client_demo.recorder import ClipRecorder

    rec = ClipRecorder()
    frame = np.zeros((48, 64, 3), dtype=np.uint8)
    assert rec.on_frame(frame, now=99.0) is frame  # not recording: preview untouched

    rec.start("Turn your head slightly left", seconds=1.0, now=100.0)
    previews = [rec.on_frame(frame, now=100.0 + i / 30) for i in range(45)]  # 1.5 s of frames at 30 fps
    frames, timestamps = rec.take()

    assert len(frames) == 30  # only frames inside the 1 s window
    assert timestamps[0] == 100.0 and timestamps[-1] < 101.0
    assert previews[0].any()  # REC overlay drawn while recording
    assert previews[-1] is frame  # recording over: preview untouched again
    assert not rec.is_recording(now=101.5)


def test_sample_frames_keeps_first_and_last():
    from client_demo.recorder import sample_frames

    frames = [np.full((2, 2, 3), i, dtype=np.uint8) for i in range(90)]
    picked = sample_frames(frames, n=8)
    assert len(picked) == 8
    assert picked[0][0, 0, 0] == 0 and picked[-1][0, 0, 0] == 89
    assert sample_frames(frames[:5], n=8) == frames[:5]
