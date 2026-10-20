# CLAUDE.md

Persistent conventions for this repo. Read `docs/PQ-Biometric-Auth-Spec.md` first
for the actual architecture/design; this file is process rules, not design
docs.

## Standing rules

- **Update `README.md` and `CHANGELOG.md` whenever behavior changes.** A
  changed endpoint, a new env var, a different default threshold, a new
  demo step - all of these need a README and/or CHANGELOG update in the
  same commit, not a follow-up.
- **Never commit datasets, model weights, or venv/node_modules.** `.gitignore`
  already excludes `datasets/*` (except its own README/download-script
  files), `*.pth`/`*.pt`/`*.onnx`/etc., `detection/weights/*` (except
  `.gitkeep`), `.venv/`, and `demo_assets/attacks/*` media files. If you add
  a new kind of large/generated artifact, add it to `.gitignore` in the same
  commit rather than after the fact.
- **Run existing tests before declaring a task finished.** `pytest tests/`
  from the repo root (see `pytest.ini` - it sets `pythonpath = .` so
  `crypto`/`detection`/`server`/etc. import without installing the package).
  If a test fails, fix it or explain why in the commit message - don't
  silently skip or delete a failing test to make the suite green.
- **State assumptions explicitly** (in the commit message and, if it affects
  how someone else should use the repo, in `README.md`'s "Assumptions"
  section too) whenever the spec doesn't pin an exact choice - e.g. which
  model checkpoint URL, which of two valid API shapes, which of two
  reasonable defaults. Don't guess silently.

## Project-specific patterns worth knowing before editing

- **`oqs` (liboqs-python) is imported lazily**, inside functions/classes in
  `crypto/kem.py` and `crypto/signature.py`, never at module top level. This
  is deliberate: it lets those modules (and pure helpers like
  `build_binding_payload`) stay importable - and their non-PQC logic
  testable - on a machine without a working native liboqs build, without
  ever substituting a different crypto library for the real one. Keep this
  pattern if you add new PQC-dependent code; don't hoist `import oqs` back
  to the top of a module.
- **`tests/conftest.py`'s `skip_if_no_oqs` marker** gates every test that
  needs a real ML-KEM/ML-DSA keypair. It's a test-environment convenience,
  not a design decision about the production code path - the production
  code always uses real liboqs (see docs/SETUP.md for the Docker/WSL2 path that
  makes it available). When adding a new PQC-dependent test, mark it with
  this rather than letting the whole test *file* fail to collect.
- **Detection modules default to `DETECTION_MODE=pretrained`, but silently
  and loudly (logged) fall back to a mock heuristic** if a checkpoint/model
  dependency isn't available - see each module's docstring in `detection/`
  and `detection/README-models.md` for exactly what mock mode computes and
  why. When adding a 6th detector or replacing a mock heuristic with a real
  model, follow this same pattern: try the real path, log a specific reason
  and fall back on any failure, never raise out of the top-level `predict()`.
- **Detection score convention**: 0.0 = certainly an attack, 1.0 = certainly
  genuine, for every module and the fused score (`detection/base.py`,
  `detection/fusion.py`). Keep new detectors on this same scale so
  `.env`'s per-module thresholds and the fusion weights stay meaningful.
- **`server/main.py`'s `_verify_core` is a short-circuit pipeline** (behind
  both `/verify` and `/verify-sealed`): the sealed channel must authenticate,
  then the Section 7 transaction-binding checks run (including
  `evidence_matches_hash`: the received frames must hash, via
  `crypto/channel.py: evidence_hash_of`, to the signed `evidence_hash`), and
  AI detection only runs (frames are even required) if all of them pass. Don't
  restructure this to run detection unconditionally - it's both spec-
  mandated (Section 7 step 7) and a real latency optimization since a
  binding-rejected request never needs to touch the 5 detectors.
- **ML-DSA signing runs in the server process; ML-KEM sealing runs in the
  client when it can** (see `README.md` "Assumptions" #2). The client
  (`client_demo/api_client.py: run_verification`) encapsulates and seals
  with AES-256-GCM via `crypto/channel.py` if `oqs` imports, else falls back
  to plaintext `/verify`. `crypto/kem.py`/`crypto/signature.py`/
  `crypto/channel.py` make no assumption about which process calls them, so
  moving signing to a real client is a caller-side change.
- **Demo samples and the self-check share one scenario list.**
  `scripts/make_demo_assets.py` builds `demo_assets/attacks/` (gitignored);
  `scripts/demo_check.py: SCENARIOS` is also imported by
  `report/scripts/system_experiments.py`, so the report's Table 10 and the
  pre-demo check cannot drift apart. If a detector change alters a scenario's
  outcome, rerun both and update the report.
- **Live Capture records over WebRTC** (`client_demo/recorder.py`). The
  frame callback runs in streamlit-webrtc's worker thread: it may only touch
  the `ClipRecorder` object, never `st.session_state` (that was the original
  live-capture bug).
- **Every decision is explained** by `server/explain.py`. When a detector's
  details or thresholds change, update its explanation text (it quotes the
  measured values and live-vs-attack reference ranges) and
  `tests/test_explain.py`.
- **Calibrate detectors on real faces, not noise.** Uniform random noise
  looks like a GAN to the FFT deepfake heuristic; use natural-statistics
  frames or face-derived samples when testing detector changes.
