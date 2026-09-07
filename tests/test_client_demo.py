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
