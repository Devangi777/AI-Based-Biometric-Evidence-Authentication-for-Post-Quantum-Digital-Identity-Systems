"""Smoke tests for detection/*.py (spec Definition of Done: "each detector's
smoke test"). These only need numpy/Pillow/imagehash - no torch, no
mediapipe, no checkpoints - since every module's mock-mode fallback is a
pure signal-processing heuristic. They verify shape/type/range correctness
and basic discriminative sanity (e.g. a blank frame vs. structured noise),
not real-world accuracy - see detection/README-models.md.
"""
from __future__ import annotations

import numpy as np
import pytest

from detection.base import DetectionResult, clip01


def _synthetic_frame(rng: np.random.Generator, sharp: bool = True) -> np.ndarray:
    if sharp:
        frame = rng.integers(0, 256, size=(200, 200, 3), dtype=np.uint8)
    else:
        base = rng.integers(100, 156, size=(200, 200, 3), dtype=np.uint8)
        frame = base  # flat/low-variance => "blurry" proxy
    return frame


def _natural_frame(rng: np.random.Generator, size: int = 240) -> np.ndarray:
    """1/f-spectrum texture (natural-image statistics) as float64."""
    fy, fx = np.fft.fftfreq(size)[:, None], np.fft.fftfreq(size)[None, :]
    f = np.hypot(fy, fx)
    f[0, 0] = 1
    chans = []
    for _ in range(3):
        img = np.real(np.fft.ifft2((rng.normal(size=(size, size)) + 1j * rng.normal(size=(size, size))) / f**1.2))
        chans.append((img - img.mean()) / img.std() * 45 + 128)
    return np.clip(np.stack(chans, -1) + rng.normal(0, 4, (size, size, 3)), 0, 255)


def _live_camera_timestamps(rng: np.random.Generator, n: int = 10) -> list[float]:
    """~30 fps with a few percent scheduling jitter, like a real webcam."""
    return list(np.cumsum(np.r_[0.0, rng.normal(1 / 30, 0.0017, n - 1)]))


def test_clip01_bounds():
    assert clip01(-5) == 0.0
    assert clip01(5) == 1.0
    assert clip01(0.3) == 0.3


def test_detection_result_clips_out_of_range_score():
    result = DetectionResult(module="x", score=1.5, is_mock=True)
    assert result.score == 1.0


class TestPresentationAttackDetector:
    def test_mock_mode_used_without_checkpoint(self):
        from detection.presentation_attack import PresentationAttackDetector

        detector = PresentationAttackDetector(mode="pretrained")
        assert detector.mode == "mock"

    def test_predict_returns_valid_score(self):
        from detection.presentation_attack import PresentationAttackDetector

        rng = np.random.default_rng(0)
        detector = PresentationAttackDetector(mode="mock")
        result = detector.predict(_synthetic_frame(rng))
        assert result.module == "presentation_attack"
        assert 0.0 <= result.score <= 1.0
        assert result.is_mock is True

    def test_flat_frame_scores_lower_than_textured_frame(self):
        from detection.presentation_attack import PresentationAttackDetector

        rng = np.random.default_rng(1)
        detector = PresentationAttackDetector(mode="mock")
        sharp = detector.predict(_synthetic_frame(rng, sharp=True))
        flat = np.full((200, 200, 3), 128, dtype=np.uint8)
        flat_result = detector.predict(flat)
        assert flat_result.score < sharp.score


class TestMorphDetector:
    def test_predict_returns_valid_score(self):
        from detection.morph_detector import MorphDetector

        rng = np.random.default_rng(2)
        detector = MorphDetector(mode="mock")  # force pixel-mirror path (no mediapipe dependency)
        result = detector.predict(_synthetic_frame(rng))
        assert result.module == "morph"
        assert 0.0 <= result.score <= 1.0
        assert result.is_mock is True

    def test_perfectly_symmetric_frame_is_handled(self):
        from detection.morph_detector import MorphDetector

        detector = MorphDetector(mode="mock")
        left_half = np.random.default_rng(3).integers(0, 256, size=(100, 100, 3), dtype=np.uint8)
        frame = np.concatenate([left_half, left_half[:, ::-1]], axis=1)
        result = detector.predict(frame)
        assert 0.0 <= result.score <= 1.0

    def test_blend_artifacts_score_lower_than_single_capture(self):
        """Ghosting (offset blend) and mirror-symmetric fine detail (blend
        with a mirrored identity) are both flagged; a single capture is not."""
        from detection.morph_detector import MorphDetector

        detector = MorphDetector(mode="mock")
        face = _natural_frame(np.random.default_rng(4))
        ghosted = (0.5 * face + 0.5 * np.roll(face, 12, axis=1)).astype(np.uint8)
        mirrored = (0.5 * face + 0.5 * face[:, ::-1]).astype(np.uint8)
        genuine = detector.predict(face.astype(np.uint8))
        assert genuine.score > 0.9
        assert detector.predict(ghosted).score < 0.5
        assert detector.predict(mirrored).score < 0.5


class TestDeepfakeDetector:
    def test_mock_mode_used_without_checkpoint(self):
        from detection.deepfake_detector import DeepfakeDetector

        detector = DeepfakeDetector(mode="pretrained")
        assert detector.mode == "mock"

    def test_predict_returns_valid_score(self):
        from detection.deepfake_detector import DeepfakeDetector

        rng = np.random.default_rng(4)
        detector = DeepfakeDetector(mode="mock")
        result = detector.predict(_synthetic_frame(rng))
        assert result.module == "deepfake"
        assert 0.0 <= result.score <= 1.0

    def test_predict_video_aggregates_as_min_of_frames(self):
        from detection.deepfake_detector import DeepfakeDetector

        rng = np.random.default_rng(5)
        detector = DeepfakeDetector(mode="mock")
        frames = [_synthetic_frame(rng) for _ in range(3)]
        video_result = detector.predict_video(frames)
        per_frame = [detector.predict(f).score for f in frames]
        assert video_result.score == pytest.approx(min(per_frame))
        assert video_result.details["num_frames"] == 3

    def test_predict_video_rejects_empty_list(self):
        from detection.deepfake_detector import DeepfakeDetector

        detector = DeepfakeDetector(mode="mock")
        with pytest.raises(ValueError):
            detector.predict_video([])


class TestReplayDetector:
    def test_first_submission_is_not_a_replay(self):
        from detection.replay_detector import ReplayDetector

        detector = ReplayDetector()
        rng = np.random.default_rng(6)
        frame = _synthetic_frame(rng)
        result = detector.check_and_record(frame, session_id="s1")
        assert result.module == "replay"
        assert result.score == 1.0
        assert result.details["best_match_hamming_distance"] is None

    def test_exact_resubmission_is_flagged_as_replay(self):
        from detection.replay_detector import ReplayDetector

        detector = ReplayDetector()
        rng = np.random.default_rng(7)
        frame = _synthetic_frame(rng)
        detector.check_and_record(frame, session_id="s1")
        result = detector.check_and_record(frame, session_id="s2")
        assert result.score == 0.0
        assert result.details["matched_session_id"] == "s1"

    def test_different_frames_are_not_flagged(self):
        from detection.replay_detector import ReplayDetector

        detector = ReplayDetector()
        rng = np.random.default_rng(8)
        detector.check_and_record(_synthetic_frame(rng), session_id="s1")
        result = detector.check_and_record(_synthetic_frame(rng), session_id="s2")
        assert result.score > 0.0

    def test_non_matching_capture_never_trips_the_veto(self):
        """Anything farther than the Hamming threshold must stay >= 0.5 (the
        fusion engine's per-module veto), so unrelated captures that happen
        to be ~10-20 bits apart are not rejected as replays."""
        from detection.replay_detector import ReplayDetector

        detector = ReplayDetector()
        rng = np.random.default_rng(10)
        base = _synthetic_frame(rng)
        detector.check_and_record(base, session_id="s1")
        near_miss = base.copy()
        near_miss[:100] = _synthetic_frame(rng)[:100]  # half the image differs
        result = detector.check_and_record(near_miss, session_id="s2")
        assert result.details["best_match_hamming_distance"] > detector.hamming_threshold
        assert result.score >= 0.5

    def test_new_capture_of_the_same_scene_is_not_a_replay(self):
        """Two genuine recordings of the same person in the same spot match on
        pHash; the fine-detail check must tell them apart from a resend."""
        import io

        from PIL import Image

        from detection.replay_detector import ReplayDetector

        def camera(img: np.ndarray, quality: int = 75) -> np.ndarray:
            """Frames arrive already compressed (webcam/browser JPEG or VP8)."""
            buf = io.BytesIO()
            Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(buf, format="JPEG", quality=quality)
            return np.asarray(Image.open(io.BytesIO(buf.getvalue())).convert("RGB"))

        rng = np.random.default_rng(11)
        scene = _natural_frame(rng)
        first = camera(scene + rng.normal(0, 3, scene.shape))
        # same person, a few pixels over, fresh sensor noise
        second = camera(np.roll(scene, 3, axis=1) + rng.normal(0, 3, scene.shape))

        detector = ReplayDetector()
        detector.check_and_record(first, session_id="s1")
        result = detector.check_and_record(second, session_id="s2")
        assert result.details["best_match_hamming_distance"] <= detector.hamming_threshold
        assert result.details["same_scene_new_capture"] is True
        assert result.score >= 0.5

        resent = camera(first, quality=85)  # the first capture sent again, re-encoded on the way
        assert detector.check_and_record(resent, session_id="s3").score == 0.0

    def test_clear_resets_store(self):
        from detection.replay_detector import ReplayDetector

        detector = ReplayDetector()
        rng = np.random.default_rng(9)
        frame = _synthetic_frame(rng)
        detector.check_and_record(frame, session_id="s1")
        detector.clear()
        result = detector.check_and_record(frame, session_id="s2")
        assert result.details["best_match_hamming_distance"] is None


class TestInjectionDetector:
    def test_mock_mode_used_without_checkpoint(self):
        from detection.injection_detector import InjectionDetector

        detector = InjectionDetector(mode="pretrained")
        assert detector.mode == "mock"

    def test_predict_without_timestamps_uses_compression_heuristic_only(self):
        from detection.injection_detector import InjectionDetector

        rng = np.random.default_rng(10)
        detector = InjectionDetector(mode="mock")
        result = detector.predict(_synthetic_frame(rng))
        assert result.details["timing_checked"] is False
        assert 0.0 <= result.score <= 1.0

    def test_predict_with_regular_timestamps_is_checked(self):
        from detection.injection_detector import InjectionDetector

        rng = np.random.default_rng(11)
        detector = InjectionDetector(mode="mock")
        timestamps = [i / 30.0 for i in range(10)]  # steady 30fps
        result = detector.predict(_synthetic_frame(rng), frame_timestamps=timestamps)
        assert result.details["timing_checked"] is True
        assert 0.0 <= result.score <= 1.0

    def test_predict_with_erratic_timestamps_scores_lower(self):
        from detection.injection_detector import InjectionDetector

        rng = np.random.default_rng(12)
        detector = InjectionDetector(mode="mock")
        frame = _synthetic_frame(rng)
        live = _live_camera_timestamps(rng)
        erratic = [0, 0.01, 0.5, 0.51, 2.0, 2.02, 2.5, 5.0, 5.01, 5.5]
        live_result = detector.predict(frame, frame_timestamps=live)
        erratic_result = detector.predict(frame, frame_timestamps=erratic)
        assert erratic_result.score < live_result.score

    def test_exactly_regular_timestamps_are_penalized(self):
        """Timestamps synthesized from a file's nominal fps (pre-recorded
        or virtual-camera stream) have zero jitter; a live camera does not."""
        from detection.injection_detector import InjectionDetector

        rng = np.random.default_rng(13)
        detector = InjectionDetector(mode="mock")
        timing_regular, _ = detector._frame_timing_heuristic([i / 30.0 for i in range(10)])
        timing_live, _ = detector._frame_timing_heuristic(_live_camera_timestamps(rng))
        assert timing_regular == 0.0
        assert timing_live == 1.0


def test_short_sequences_are_not_judged_on_timing():
    """A handful of intervals can't tell a camera from a file (live jitter
    reads as "machine-perfect" by chance), so timing needs >= 8 intervals."""
    from detection.injection_detector import InjectionDetector

    detector = InjectionDetector(mode="mock")
    for seed in range(50):
        score, details = detector._frame_timing_heuristic(_live_camera_timestamps(np.random.default_rng(seed), n=5))
        assert score == 1.0 and details["timing_checked"] is False
    _, details = detector._frame_timing_heuristic(_live_camera_timestamps(np.random.default_rng(0), n=9))
    assert details["timing_checked"] is True
