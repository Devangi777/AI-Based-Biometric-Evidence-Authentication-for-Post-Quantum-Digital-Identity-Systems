# Changelog

All notable changes to this project are recorded here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); dates are when the
change was made, not a formal release schedule (this is a prototype, not a
versioned package).

## [Unreleased]

Initial build, per `PQ-Biometric-Auth-Spec.md`, in the order specified by
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
