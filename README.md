# AI-Based Biometric Evidence Authentication for Post-Quantum Digital Identity Systems

A prototype that combines **post-quantum cryptography** (ML-KEM-768 / ML-DSA-65
via `liboqs`/`oqs-python`), **AI-based biometric attack detection** (presentation
attack, morphing, deepfake, replay, injection), and a **transaction-binding /
freshness mechanism** to verify that a submitted face capture is genuine, live,
unmanipulated, and freshly captured for a specific verification session — over
a channel secured against quantum adversaries.

Full design rationale lives in [`PQ-Biometric-Auth-Spec.md`](PQ-Biometric-Auth-Spec.md).
This README documents what was actually built and any assumptions made where
the spec left something open.

## Why this exists

Cryptography secures the *channel*. It says nothing about whether the
*biometric evidence* flowing through that channel is genuine. This project
shows both halves working together: a secure PQC channel **and** an AI
pipeline that catches deepfakes, morphs, spoofed presentations, replayed
evidence, and injected streams — bound to a single-use session nonce so even
a genuine, previously-captured sample can't be replayed.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                            CLIENT SIDE                                │
│  ┌──────────────┐    ┌───────────────────┐    ┌──────────────────┐  │
│  │ Camera/Sensor│───▶│ Local pre-checks    │───▶│ Session Nonce +   │  │
│  │ Capture       │    │ (frame quality,    │    │ Challenge-Response │  │
│  │               │    │ face detection)     │    │ (liveness prompt)  │  │
│  └──────────────┘    └───────────────────┘    └──────────────────┘  │
│                                                          │            │
│                                                          ▼            │
│                                          ┌──────────────────────────┐│
│                                          │ Evidence Hash + Metadata ││
│                                          │ (SHA-256 of frame/video, ││
│                                          │ timestamp, session_id)   ││
│                                          └──────────────────────────┘│
│                                                          │            │
│                                                          ▼            │
│                                          ┌──────────────────────────┐│
│                                          │ ML-DSA Signature over    ││
│                                          │ (hash ‖ session_id ‖ ts) ││
│                                          └──────────────────────────┘│
└─────────────────────────────────────────┼─────────────────────────────┘
                                           │
                              ML-KEM-encrypted channel
                                           │
┌──────────────────────────────────────────▼─────────────────────────────┐
│                            SERVER SIDE                                  │
│  ┌────────────────────┐   ┌─────────────────────────────────────────┐ │
│  │ ML-KEM Decapsulate  │──▶│ ML-DSA Verify (signature, freshness,    │ │
│  │ (session key)       │   │ session_id match, timestamp window)     │ │
│  └────────────────────┘   └─────────────────────────────────────────┘ │
│                                           │                             │
│                                           ▼                             │
│                          ┌─────────────────────────────────┐          │
│                          │   AI ATTACK-DETECTION PIPELINE   │          │
│                          │  1. Presentation-Attack (PAD)    │          │
│                          │  2. Face-Morphing Detector       │          │
│                          │  3. Deepfake Detector            │          │
│                          │  4. Replay Detector (pHash vs DB)│          │
│                          │  5. Injection Detector           │          │
│                          └───────────────────┬───────────────┘          │
│                                              ▼                          │
│                          ┌──────────────────────────────────┐          │
│                          │ Decision Engine (fusion of scores)│          │
│                          │ → ACCEPT / REJECT + confidence    │          │
│                          └──────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────────┘
```

See [`PQ-Biometric-Auth-Spec.md`](PQ-Biometric-Auth-Spec.md) Section 3 for the
canonical diagram and Section 7 for the transaction-binding sequence.

## Repository layout

```
crypto/         ML-KEM / ML-DSA wrappers (oqs-python) + classical RSA/ECDSA baseline
detection/      5 attack-detection modules + fusion engine
binding/        Session nonce / challenge / freshness enforcement (Section 7)
server/         FastAPI app tying crypto + binding + detection together
client_demo/    Streamlit demo (live webcam mode + simulate-attack mode)
evaluation/     Benchmark harness producing Section 8 metrics as CSV + charts
demo_assets/    Small, self-generated demo files for "Simulate Attack" mode
datasets/       Gitignored - download scripts only, see datasets/download_samples.md
tests/          Unit tests: crypto round-trip, detector smoke tests, binding logic
```

## Quick start

**This project uses a split architecture on Windows** (see [SETUP.md](SETUP.md)
for why): the crypto + AI server runs in Docker (Linux, where `liboqs` builds
cleanly), and the Streamlit demo runs natively on Windows for webcam access.

```bash
# 1. Server (Docker)
cp .env.example .env
docker compose up --build
# health check:
curl http://localhost:8000/health

# 2. Client demo (native Windows Python)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-client.txt
streamlit run client_demo/streamlit_app.py
```

Full step-by-step instructions, including what to do if `docker` isn't
installed yet: **[SETUP.md](SETUP.md)**.
Presenting the live demo: **[DEMO_GUIDE.md](DEMO_GUIDE.md)**.

## Assumptions made where the spec was open-ended

These are called out here (per the spec's own instruction to state
assumptions explicitly rather than guess silently) and are also noted in the
commit messages that introduced them:

1. **Python version on the Windows host.** The spec targets Python 3.11; the
   machine this was built on has Python 3.10 natively installed (no 3.11
   found on PATH). Native Windows use is limited to the Streamlit client
   anyway (see #2), which is not version-sensitive; the Dockerfile pins
   `python:3.11-slim` for the server, matching the spec exactly where it
   matters (the crypto/AI layer). If you set up a native Python 3.11 venv on
   Windows, everything here still works unchanged.

2. **Where client-side ML-DSA signing actually runs.** Section 3 shows the
   *client* computing the evidence hash and signing it with ML-DSA before
   sending it over the ML-KEM channel. Section 11 also says the Streamlit
   demo should run natively on Windows for webcam access, split from the
   Dockerized crypto/AI server. Literally following both at once would
   require `oqs-python` (and thus a working liboqs native build) on the
   Windows host running Streamlit — which is exactly the install failure
   Section 11 exists to avoid.

   **Resolution:** in this prototype, *all* PQC operations (ML-KEM
   encapsulation/decapsulation **and** ML-DSA signing/verification) are
   performed by the Dockerized `server/` process, which exposes them as
   distinct "as-client" and "as-server" endpoints/functions
   (`server/main.py`: `POST /session/{id}/sign-evidence` acts as the client
   signer, `POST /session/{id}/verify` acts as the server verifier). The
   Streamlit app only computes the SHA-256 evidence hash locally (no PQC
   library needed for that) and orchestrates calls to the server for
   everything cryptographic. This preserves the actual protocol being
   demonstrated (nonce/timestamp/challenge-bound ML-DSA signature verified
   server-side, ML-KEM-derived channel key) without requiring a second
   native liboqs build. It does **not** demonstrate a hardened, physically
   separate client device holding its own private key — that would be the
   natural next step for a production system and is documented here rather
   than silently glossed over. `crypto/kem.py` and `crypto/signature.py` are
   written as plain reusable wrappers with no assumption about which process
   calls them, so this can be changed later by simply pointing a real client
   process at them once liboqs is available there too (e.g. once teammates
   run the whole stack in Docker/WSL2, or install VS Build Tools + CMake +
   Ninja natively).

3. **Docker Desktop is not installed on this machine.** `docker`/`docker
   compose` are unavailable in this environment, so the `docker-compose.yml`
   / `Dockerfile` here are written and reviewed carefully against liboqs's
   documented build requirements but have **not** been build-tested end to
   end in this environment. `python -c "import oqs"` **was** tested natively
   on Windows here and confirmed to fail exactly as Section 11 predicts
   (`cmake` not found during liboqs's self-build step) — confirming the
   Docker/WSL2 fallback is the right path rather than a precaution taken on
   faith. Before the live demo, run through SETUP.md's verification steps
   once to confirm the image builds on your machine.

4. **AI detection checkpoints are not downloaded in this environment.** No
   internet-downloaded model weights are bundled in the repo (per the task
   instructions and `.gitignore`). Every detector in `detection/` has a
   documented pretrained path (exact source, per Section 6) and a deterministic
   **mock mode** fallback that runs with zero downloads so the full pipeline
   (crypto → binding → detection → fusion) is exercisable and testable today.
   See `detection/README-models.md` for exactly what to download and where to
   put it to switch each module from mock to pretrained.

## Development conventions

See [CLAUDE.md](CLAUDE.md) for standing rules followed in this repo (update
README/CHANGELOG on behavior change, never commit datasets/weights/venvs, run
tests before declaring work done, state assumptions explicitly).
