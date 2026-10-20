# Changelog

All notable changes to this project are recorded here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); dates are when the
change was made, not a formal release schedule (this is a prototype, not a
versioned package).

## [Unreleased]

### Fixed (live webcam use)

- **Every real webcam frame was rejected as a presentation attack.** PAD
  divided whole-frame sharpness by 500, a scale only a sharp still photo
  reaches; webcam frames (15-50) scored 0.35-0.46, under the veto. PAD now
  combines three recapture cues measured on the face region: true-black
  level (0.5), sharpness at a fixed face size (0.3) and saturation (0.2).
  Simulated webcam frames (dim, soft, plain wall, small face) score 1.00;
  the printed-photo sample 0.01, the screen replay 0.41.
- **A person's second genuine recording was rejected as a replay.** Two
  recordings of the same scene match on perceptual hash; replay now also
  requires the native-resolution fine detail to match (same capture >= 0.85,
  new recording <= 0.41 after 2 px of movement). Same-scene new captures
  score 0.75 and never veto.
- **Injection timing misjudged short sequences** (2% of 4-interval live
  sequences read as machine-perfect). Timing is judged only on >= 8
  intervals, with a robust MAD-based jitter; video files and recordings now
  send every frame's timestamp.
- **Client quality check** flagged normal webcam sharpness as "too blurry"
  (threshold 40 -> 10).

### Added

- **Recorded liveness challenge.** Live Capture records a 4 s clip from the
  browser camera over WebRTC (`client_demo/recorder.py`, streamlit-webrtc
  re-added), with a REC bar and on-video prompts; 8 frames plus all
  timestamps are sent. Two-photo fallback kept.
- **Explanations.** Every response carries `explanations` (plain-language
  reasons with measured values, `server/explain.py`) and `liveness` (what
  the challenge check measured); the dashboard shows them under each REJECT
  and `demo_check.py --explain` prints them.
- `detection/face_region.py` shared by PAD and morph; `GUIDE.md`
  (presenter's guide, replaces `docs/DEMO_GUIDE.md`); README restructured
  for a public audience.

### Changed

- Demo videos are 1 s / 30 frames, long enough for the timing check.
- Synthetic test frames use correlated colour channels (camera-like).
- `docker-compose.yml`: removed the obsolete `version` key.

## [0.2.0] - sealed channel and real-face fixes

### Fixed (found by testing with a real face and the real client)

- **Morph detector rejected genuine faces.** Landmark symmetry scored a real
  frontal face 0.43 (below the 0.5 veto) and fell back to whole-frame
  mirror asymmetry (score 0) whenever MediaPipe missed the face. Rewritten
  around the artifacts pixel-averaged morphs actually leave: ghost-peak
  prominence in the 2-D autocorrelation and mirror symmetry of the high-pass
  detail in the face region (`detection/morph_detector.py`).
- **Replay detector widened its own radius.** Non-matching captures scored
  (d - 8)/24, so anything closer than ~20 bits fell under the 0.5 veto and
  3/40 genuine sessions were rejected. Non-matches now score >= 0.5.
- **Injection detector rewarded synthetic timing.** Exactly regular frame
  timestamps (pre-recorded file / virtual camera) scored 0.75; they now
  score 0.
- **Frames were not tied to the signature.** The server never checked that
  the frames it analysed hash to the signed `evidence_hash`; it now does
  (`evidence_matches_hash` binding check, canonical length-prefixed hash in
  `crypto/channel.py`).
- **The ML-KEM channel key was never used.** New `POST /session/{id}/verify-sealed`:
  the client encapsulates and seals the payload with AES-256-GCM
  (HKDF(K, salt=nonce), session id as AAD); `/verify` remains for clients
  without liboqs.
- **Live capture never delivered a frame** (streamlit-webrtc callback wrote
  `st.session_state` from a worker thread). Replaced with `st.camera_input`;
  `streamlit-webrtc`/`av` removed from `requirements-client.txt`.
- **PAD sharpness depended on camera resolution**; now measured at a 640 px
  long side.
- **Benchmark "genuine" frames were white noise**, which the FFT deepfake
  heuristic correctly flags; `evaluation/benchmark.py` now uses
  natural-statistics frames.

### Added

- `scripts/make_demo_assets.py` (demo samples from one consenting face
  photo) and `scripts/demo_check.py` (12-scenario pre-demo self-check).
- Dashboard: *Tamper with Protocol* tab, per-layer result panel, local
  capture quality check, replay-memory reset; `DEMO_MODE` setting and
  `POST /demo/reset-replay-store` (403 unless enabled).
- `liveness_check_ms` timing, separate from the cryptographic
  `binding_check_ms`; per-detector `detection_details` in responses.
- `report/` (final report, figures, data, experiment scripts including the
  Qiskit circuits) and `docs/ARCHITECTURE.md`.
- Tests: sealed channel, frame substitution, timing and replay-veto
  regressions, morph artifacts, quality check, demo-mode guard (94 total).

### Changed

- Documentation moved to `docs/` (setup, demo guide, spec, study guide).

## [0.1.0] - initial build

Initial build, per `docs/PQ-Biometric-Auth-Spec.md`, in the order specified by
the build instructions. Each stage below was a separate commit; see git log
for full detail.

### Added

- **Repo scaffolding**: README.md, SETUP.md, .env.example, requirements.txt
  + requirements-client.txt (server/Docker vs. native-Windows-client split),
  docker-compose.yml, Dockerfile, .gitignore.
- **Crypto layer** (`crypto/`): ML-KEM-768 (`kem.py`) and ML-DSA-65
  (`signature.py`) wrappers over `oqs-python`/liboqs, plus an RSA-3072/
  ECDSA-P256 classical baseline (`classical_baseline.py`) for the
  PQC-vs-classical overhead comparison.
- **FastAPI server** (`server/`): session lifecycle, ML-KEM channel
  establishment, ML-DSA evidence signing/verification.
- **Session binding** (`binding/session_binding.py`): the Section 7
  transaction-binding/freshness mechanism - nonce single-use, timestamp
  freshness window, signature validity, and challenge fulfilment.
- **AI detection pipeline** (`detection/`): presentation-attack, face-morph,
  deepfake, replay, and injection detectors, each with a documented
  mock-mode fallback when a pretrained checkpoint isn't available (see
  `detection/README-models.md`), plus the weighted-average fusion/decision
  engine (`fusion.py`) and the liveness-challenge verifier
  (`liveness_challenge.py`) that binding/session_binding.py's challenge
  check delegates to.
- **Streamlit demo client** (`client_demo/`): live webcam capture mode and a
  simulate-attack mode over `demo_assets/attacks/`, with real-time
  per-detector scores, fused decision, latency breakdown, and an
  append-only attempt log.
- **Evaluation harness** (`evaluation/`): crypto/detection latency, PQC vs.
  classical overhead, process CPU/memory overhead, and (server permitting)
  throughput vs. concurrency, written as CSV + charts.
- **Documentation**: `DEMO_GUIDE.md` (numbered live-demo script),
  `demo_assets/README-assets.md`, `detection/README-models.md`,
  `datasets/download_samples.md`, this file, and `CLAUDE.md`.

### Notes on this environment

Built on a Windows machine without Docker Desktop installed and without a
working native liboqs build toolchain (confirmed: `cmake` unavailable to
liboqs-python's self-build step). Every ML-KEM/ML-DSA-dependent test is
present and correct but skips automatically in this environment rather than
being faked - see `tests/conftest.py` and `SETUP.md`. All non-PQC-dependent
tests pass. See `README.md` "Assumptions" for the full list of decisions
made where the spec didn't pin an exact choice.
