# AI-Based Biometric Evidence Authentication for Post-Quantum Digital Identity Systems
### Technical Specification & Implementation Guide

**Team size:** 3 | **Timeline:** 5-week sprint (+1 buffer week) | **Compute:** Laptop + Colab/Kaggle GPU

---

## 1. Project Overview

Digital identity systems rely on cryptography to secure *channels* and *data at rest*, but cryptographic security says nothing about whether the biometric evidence flowing through that channel is genuine. An attacker can compromise a perfectly secure TLS/PQC channel and still submit a deepfake video, a morphed face photo, a replayed recording, or an injected video stream — and the crypto layer will faithfully protect and deliver that fraudulent evidence.

This project builds a prototype that combines:
1. **Post-quantum cryptography** (ML-KEM for key exchange, ML-DSA for signatures) to protect the communication and authentication layer against future quantum adversaries ("harvest now, decrypt later" threat).
2. **AI-based biometric attack detection** to verify the *authenticity* of the biometric evidence itself, independent of channel security.
3. **A transaction-binding / freshness mechanism** that cryptographically ties a specific biometric capture to a specific verification session, preventing replay of previously captured (even genuine) biometric evidence.

The system is evaluated on both **security** (detection accuracy across attack types) and **performance** (latency, throughput, CPU/memory overhead — especially the overhead PQC adds vs. classical ECDSA/RSA).

---

## 2. Use Case

**Primary use case:** Remote identity verification (e.g., onboarding for a bank, e-KYC, government digital ID) where a user submits a live face capture over the network to a verification server.

**Actors:**
- **Legitimate user** — submits live biometric capture during a verification session.
- **Attacker** — attempts one of five attack types:
  - *Presentation attack* — printed photo, screen replay, or mask held up to camera
  - *Face morphing* — a blended image of two identities submitted to pass as either
  - *Deepfake* — synthetically generated/altered face video
  - *Replay attack* — a previously captured genuine biometric sample re-submitted
  - *Injection attack* — a fake video stream injected directly into the capture pipeline (bypassing the physical camera)
- **Verification server** — orchestrates the session, runs detection, validates PQC signatures, issues verification decision.

**User story:**
> "As a digital identity platform, I want to verify that a face capture is (a) from a real, live human, (b) not synthetically generated or manipulated, (c) freshly captured for *this specific* session, and (d) transmitted over a channel secure against quantum adversaries — so that I can trust the verification result today and have that trust hold up even after quantum computers become practical."

---

## 3. System Architecture

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
│                          │  ┌─────────────────────────────┐│          │
│                          │  │ 1. Presentation-Attack (PAD) ││          │
│                          │  │ 2. Face-Morphing Detector    ││          │
│                          │  │ 3. Deepfake Detector         ││          │
│                          │  │ 4. Replay Detector (hash/    ││          │
│                          │  │    perceptual match vs DB)   ││          │
│                          │  │ 5. Injection Detector        ││          │
│                          │  │    (sensor/consistency check)││          │
│                          │  └─────────────────────────────┘│          │
│                          └───────────────────┬───────────────┘          │
│                                              ▼                          │
│                          ┌──────────────────────────────────┐          │
│                          │ Decision Engine (fusion of scores)│          │
│                          │ → ACCEPT / REJECT + confidence    │          │
│                          └──────────────────────────────────┘          │
│                                              │                          │
│                                              ▼                          │
│                          ┌──────────────────────────────────┐          │
│                          │ Evaluation Logger                 │          │
│                          │ (latency, CPU%, mem, accuracy log)│          │
│                          └──────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Tech Stack (with rationale)

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.11 | Best ecosystem overlap between PQC bindings (oqs-python) and ML/CV libraries (PyTorch, OpenCV) |
| PQC library | **liboqs** via **oqs-python** | Reference implementation of NIST-standardized ML-KEM (FIPS 203) and ML-DSA (FIPS 204), maintained by the Open Quantum Safe project; widely used in PQC research prototypes |
| Backend/testbed | FastAPI | Async support (needed for streaming video frames), auto-generated OpenAPI docs, lightweight for a 5-week build |
| AI/ML framework | PyTorch + torchvision | Best pretrained-model availability for face forensics/anti-spoofing research; easy fine-tuning |
| Face detection/landmarks | MediaPipe / RetinaFace | Fast, CPU-friendly, needed as a preprocessing step before all detectors |
| Frontend/demo | Streamlit | Fastest way to build an interactive demo for camera capture + live verification result, no separate frontend team needed |
| Containerization | Docker + docker-compose | Reproducibility requirement from the objectives ("working and reproducible prototype") |
| Evaluation/metrics | scikit-learn, psutil, time/perf_counter | Standard metrics (accuracy, FAR/FRR, APCER/BPCER) + system resource monitoring |
| Experiment tracking | Weights & Biases (free tier) or simple CSV/JSON logging | Given short timeline, CSV/JSON logging is likely sufficient; W&B optional if team wants nicer plots |

---

## 5. Post-Quantum Cryptography Layer — Detailed Implementation

### 5.1 Why ML-KEM and ML-DSA specifically
- **ML-KEM** (Module-Lattice Key Encapsulation Mechanism, FIPS 203, derived from CRYSTALS-Kyber) is NIST's standardized algorithm for key exchange, replacing RSA/ECDH for establishing a shared secret resistant to Shor's algorithm.
- **ML-DSA** (Module-Lattice Digital Signature Algorithm, FIPS 204, derived from CRYSTALS-Dilithium) is NIST's standardized signature scheme, replacing RSA/ECDSA signatures.
- Both are lattice-based, which is currently the most mature and widely deployed post-quantum family (also used in TLS 1.3 PQC hybrid modes already being rolled out by browsers/CAs).

### 5.2 Library: liboqs / oqs-python

```bash
# Install liboqs (C library) then the Python wrapper
pip install liboqs-python
```

```python
import oqs

# --- ML-KEM: session key establishment ---
kem_alg = "ML-KEM-768"  # NIST security level 3 (192-bit classical security)

# Server side: generate keypair, publish public key
with oqs.KeyEncapsulation(kem_alg) as server_kem:
    server_public_key = server_kem.generate_keypair()

    # Client side: encapsulate against server's public key
    with oqs.KeyEncapsulation(kem_alg) as client_kem:
        ciphertext, shared_secret_client = client_kem.encap_secret(server_public_key)

    # Server decapsulates to derive the same shared secret
    shared_secret_server = server_kem.decap_secret(ciphertext)
    assert shared_secret_client == shared_secret_server
    # shared_secret is then used as an AES-256-GCM key for the actual video/data channel
```

```python
# --- ML-DSA: signing biometric evidence for transaction binding ---
sig_alg = "ML-DSA-65"  # NIST security level 3

with oqs.Signature(sig_alg) as client_sig:
    client_public_key = client_sig.generate_keypair()

    message = evidence_hash + session_id.encode() + timestamp.encode()
    signature = client_sig.sign(message)

# Server verifies:
with oqs.Signature(sig_alg) as verifier:
    is_valid = verifier.verify(message, signature, client_public_key)
```

**Recommended parameter sets:** `ML-KEM-768` and `ML-DSA-65` (NIST Level 3) — a good balance of security margin and performance for a prototype; avoid Level 5 (`ML-KEM-1024`/`ML-DSA-87`) unless the team specifically wants to measure the heavier overhead too (worth doing as one comparison point in the evaluation).

### 5.3 Hybrid consideration (optional stretch goal)
Real-world PQC rollouts (e.g., TLS 1.3 X25519+ML-KEM hybrids) combine a classical algorithm with the PQC one so security doesn't regress if a flaw is later found in the new scheme. If time permits, implement `X25519+ML-KEM-768` hybrid via liboqs's hybrid KEM support — this is also a good talking point for the "practical benefits and limitations" analysis objective.

### 5.4 Classical baseline for comparison
Implement the same channel using RSA-3072 (key exchange via RSA-OAEP) and ECDSA-P256 (signatures) via Python's `cryptography` library, to produce the PQC-vs-classical overhead numbers required by the evaluation objective.

---

## 6. AI Biometric Attack Detection — Detailed Implementation

For each module below: use a **pretrained model first**, fine-tune only if time and Colab GPU hours allow. This is the realistic path for a 5-week, 3-person, laptop-based sprint.

### 6.1 Presentation Attack Detection (PAD) — photo/screen/mask spoofing
- **Model:** Silent-Face-Anti-Spoofing (MiniFASNet) — lightweight, CPU-inference-friendly, pretrained weights publicly available.
- **Dataset:** CelebA-Spoof (subset) or CASIA-FASD for evaluation.
- **Why:** Purpose-built for exactly this attack category; small enough to run without GPU at inference time, which matters given laptop-only deployment for the live demo.

### 6.2 Face Morphing Detection
- **Approach:** Feature-based morphing artifact detection (e.g., analyzing texture/frequency-domain inconsistencies with a CNN classifier) or use a pretrained MTCNN + landmark-symmetry deviation model.
- **Dataset:** AMSL Face Morph Image Dataset (public, small enough for a subset evaluation) — request access early since some morphing datasets require an approval form (flag this in the professor email follow-up).
- **Fallback if dataset access is delayed:** Generate a small synthetic morph set yourselves using open morphing tools (e.g., `face_morpher` Python package) on a public face dataset (with appropriate attribution/ethics note in the report).

### 6.3 Deepfake Detection
- **Model:** Xception or EfficientNet-B4 fine-tuned on FaceForensics++ (many pretrained checkpoints are publicly shared by the research community) — or use a lightweight MesoNet/Meso4 model if Colab GPU time is limited.
- **Dataset:** FaceForensics++ (c23 compressed subset — full dataset is large; use the documented subset request process).
- **Why:** Xception-on-FF++ is the most cited/benchmarked baseline in deepfake detection literature, making your results easy to contextualize against published numbers.

### 6.4 Replay Attack Detection
- **Approach:** Not a classifier — a **freshness/matching check**. Maintain a short-term perceptual hash (pHash) store of recently submitted biometric evidence per session; reject if a new submission's pHash matches a prior one within a time window, or if capture metadata (device sensor noise pattern, EXIF-like data) matches a previously seen sample exactly.
- **Why this design:** Replay attacks resubmit *genuine* data, so a content classifier can't catch them — only session/freshness binding can, which is why this ties directly into Section 7.

### 6.5 Injection Attack Detection
- **Approach:** Sensor-consistency and pipeline-integrity checks — verify the capture came from an expected camera API/driver path (not a virtual camera), check frame-rate/timestamp consistency, and apply a lightweight CNN to detect virtual-camera/injected-stream artifacts (compression signatures inconsistent with a real live camera feed).
- **Dataset:** Limited public datasets exist here; this module is the most research-y — document it clearly as a heuristic + ML hybrid rather than a fully solved classifier, and be upfront about this limitation in the final analysis (this is a legitimate and expected finding, not a shortcoming to hide).

### 6.6 Fusion / Decision Engine
Combine the five module scores into a single ACCEPT/REJECT decision. Start simple: **weighted score fusion** with per-module thresholds tuned on a validation split; a learned fusion (small logistic regression over the 5 scores) is a good stretch goal if time allows.

---

## 7. Transaction-Binding & Freshness Mechanism

This is the piece that connects Sections 5 and 6 — it's the novel integration point of the project, not just "crypto + AI side by side."

**Design:**
1. Server issues a **session nonce** (random, single-use) and a **liveness challenge** (e.g., "turn head left," random digit to speak) at session start.
2. Client captures biometric evidence *while fulfilling the challenge*.
3. Client computes `evidence_hash = SHA-256(frame_bytes)`.
4. Client constructs `binding_payload = evidence_hash ‖ session_nonce ‖ timestamp ‖ challenge_response`.
5. Client signs `binding_payload` with **ML-DSA**.
6. Server verifies: (a) signature validity, (b) `session_nonce` matches the one it issued and hasn't been used before, (c) `timestamp` is within an acceptable freshness window (e.g., 30 seconds), (d) challenge was correctly fulfilled (checked by the AI pipeline, e.g., did the head actually turn left in the frames).
7. Only if all four checks pass does the evidence proceed to the AI attack-detection pipeline.

This mechanism is what prevents replay of even a **genuine** previously-captured biometric sample — the nonce and challenge make each session's required evidence unique.

---

## 8. Evaluation Methodology

| Metric | How measured |
|---|---|
| Detection accuracy | Per-module accuracy, precision, recall, F1 on held-out test splits |
| Attack-detection rate | APCER (Attack Presentation Classification Error Rate), BPCER (Bona-fide Presentation Classification Error Rate) — standard ISO/IEC 30107-3 metrics for PAD-style evaluation |
| Latency | End-to-end time from evidence capture to ACCEPT/REJECT decision (`time.perf_counter()`), broken down by stage (crypto, per-detector, fusion) |
| Throughput | Verifications/second under simulated concurrent load (use `locust` or simple asyncio load generator) |
| CPU/Memory overhead | `psutil` sampling during PQC operations vs. classical baseline, and during AI inference |
| PQC overhead specifically | Compare ML-KEM/ML-DSA operation time + payload size vs. RSA-3072/ECDSA-P256 equivalents, isolated from AI pipeline cost |

**Output:** A results table/plot set (bar charts: latency per stage; line chart: throughput vs. concurrent sessions; table: accuracy per attack type) — feed these into the final report and demo.

---

## 9. Repository Structure (suggested)

```
pq-biometric-auth/
├── crypto/
│   ├── kem.py              # ML-KEM wrapper (oqs-python)
│   ├── signature.py        # ML-DSA wrapper
│   └── classical_baseline.py
├── detection/
│   ├── presentation_attack.py
│   ├── morph_detector.py
│   ├── deepfake_detector.py
│   ├── replay_detector.py
│   └── injection_detector.py
├── binding/
│   └── session_binding.py  # nonce, challenge, freshness checks
├── server/
│   └── main.py              # FastAPI app
├── client_demo/
│   └── streamlit_app.py
├── evaluation/
│   ├── benchmark.py
│   └── metrics.py
├── datasets/                # gitignored, download scripts only
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 10. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Dataset access delays (FaceForensics++, morphing datasets require request forms) | Request access in Week 1, Day 1; have a synthetic/fallback dataset plan ready |
| GPU time on Colab too limited for fine-tuning all 3 CV models | Prioritize deepfake > morphing > PAD for fine-tuning; PAD model (MiniFASNet) is CPU-friendly out of the box |
| liboqs installation issues across team members' machines | Standardize on Docker early (Week 1) so crypto environment is identical for everyone |
| Injection attack detection is genuinely under-researched | Document as heuristic-based with clearly stated limitations — this is a valid, expected finding for the trade-off analysis objective |
| Scope creep across 5 attack types + PQC + eval in 5 weeks | Keep fusion simple (weighted average) initially; only attempt learned fusion if ahead of schedule |

---

## 11. Windows Development Environment & Setup Strategy

**Problem:** `liboqs` (the C library behind `oqs-python`) sometimes has no prebuilt wheel for a given Windows/Python combo, and building it from source natively requires Visual Studio Build Tools, CMake, and Ninja — a common place for an AI coding agent to get stuck silently swapping in a different crypto library. This section exists so that doesn't happen.

**Setup order to try, in this priority:**
1. **Try the pip wheel first:** `pip install liboqs-python` on native Windows Python 3.11. If `import oqs` works and a basic keygen succeeds, stop here — no further setup needed.
2. **If the wheel install fails, use a split architecture (recommended fallback):**
   - Run the **server** (crypto layer + AI detection pipeline, `server/`, `crypto/`, `detection/`) inside **Docker Desktop with the WSL2 backend**, where liboqs builds cleanly on Linux.
   - Run the **Streamlit demo app** (`client_demo/`) **natively on Windows Python**, since webcam access via `streamlit-webrtc` is simplest directly on the host OS.
   - The two communicate over `localhost:8000` via the FastAPI REST/WebSocket API — so the split is invisible to the demo experience.
3. **Do not** silently substitute a different PQC library (e.g., a pure-Python toy implementation) if liboqs is hard to install — that defeats the point of the project (using NIST-standardized, audited implementations). Escalate the setup problem to the user in README.md/SETUP.md instead.

**SETUP.md must include**, step by step: Python 3.11 venv creation, Docker Desktop + WSL2 enablement instructions, the `oqs-python` install-and-test snippet from Section 5.2, and how to verify the split architecture is talking correctly (a `curl` or `httpie` health-check command).

---

## 12. Demo Mode Design (Live Webcam + Sample Attack Files)

The Streamlit demo (`client_demo/streamlit_app.py`) must support **two input modes**, selectable via a toggle/tab:

**Mode 1 — Live Capture (legitimate user flow):**
- Uses `streamlit-webrtc` to access the real webcam.
- Server issues a session nonce + liveness challenge (e.g., "turn your head left," or "say the number shown on screen").
- User performs the challenge live; the full pipeline (Sections 5–7) runs against the live capture.

**Mode 2 — Simulate Attack:**
- A dropdown to pick one of the five attack types.
- Loads a file from a bundled `demo_assets/attacks/` folder (or lets the user upload their own), and feeds it through the same pipeline as if it were a live submission.
- Bundled files needed (small, demo-safe, NOT full research datasets — do not auto-download FaceForensics++/AMSL/CelebA-Spoof into this folder):
  - `presentation_photo.jpg` — a photo of a face held up to a camera (team can self-capture)
  - `presentation_screen_replay.mp4` — a face video played back on a phone/monitor and recaptured
  - `morphed_face.jpg` — one sample morph (self-generated with the `face_morpher` package on two team members' photos is acceptable for demo purposes)
  - `deepfake_sample.mp4` — one public-domain/sample deepfake clip
  - `replay_sample.jpg` — a copy of a previously-accepted genuine capture, resubmitted to demonstrate the freshness/nonce rejection
  - `injection_sample.mp4` — a screen-recorded or virtual-camera-sourced clip

**Real-time feedback requirement:** the UI must show, live as each run completes: per-detector scores, the fused ACCEPT/REJECT decision, a latency breakdown (crypto vs. detection vs. total), and an append-only log table of recent verification attempts — this is what makes the demo feel "real-time" rather than a single static result.

Include a `demo_assets/README-assets.md` explaining exactly what each file should be and how to (re)create it, plus a note that these are demo-scale substitutes, not the full evaluation datasets used in Section 8.

---

## 13. Repository Deliverables Checklist (Definition of Done)

- [ ] Git repo initialized with incremental, meaningful commits (not one giant commit)
- [ ] `README.md` — overview, architecture diagram, quick-start, links to SETUP.md and DEMO_GUIDE.md
- [ ] `SETUP.md` — Windows-specific step-by-step setup per Section 11
- [ ] `DEMO_GUIDE.md` — exact numbered steps to run and present the live demo (what to click, what to say for each of the 5 attack types, what the audience should see)
- [ ] `.env.example` — configurable algorithm choice (ML-KEM-768 vs -1024, ML-DSA-65 vs -87), detection thresholds, freshness window
- [ ] `requirements.txt` with pinned versions
- [ ] `docker-compose.yml` for the server-side stack
- [ ] Unit tests: crypto round-trip (keygen/encap/decap, sign/verify), each detector's smoke test, session-binding freshness logic
- [ ] `evaluation/benchmark.py` producing a results CSV + basic charts for the Section 8 metrics
- [ ] `CHANGELOG.md` initialized for tracking future updates
- [ ] `CLAUDE.md` at repo root — persistent project conventions for future agent sessions (see Section 14)

---

## 14. Working With the Coding Agent — Iteration & Update Workflow

Create a `CLAUDE.md` file at the repo root (Claude Code and Cursor's agent both read this automatically) containing standing rules, e.g.:
- Always update `README.md` and `CHANGELOG.md` when behavior changes
- Never commit datasets, model weights, or venv/node_modules
- Run existing tests before declaring a task finished; if a test fails, fix it or explain why in the commit message
- State assumptions explicitly (e.g., which model checkpoint URL was used) in commit messages when the spec doesn't pin an exact one

**For follow-up changes after initial generation, be specific and reference exact files.** Examples of good follow-up prompts:
- "Add a confidence-threshold slider to the Streamlit UI in `client_demo/streamlit_app.py` and wire it into the fusion logic in `detection/fusion.py`. Update `DEMO_GUIDE.md` if the demo steps change."
- "The ML-DSA verification in `server/main.py` fails silently on an expired timestamp — add explicit rejection-reason logging and a test in `tests/test_binding.py`."
- "Regenerate `evaluation/benchmark.py`'s latency chart to break down PQC vs. classical baseline overhead separately, per Section 8."

Vague prompts like "make it better" or "fix the demo" will get worse results than specific, file-scoped ones.

---

## 15. References
- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- Open Quantum Safe project — liboqs / oqs-python
- FaceForensics++ dataset and benchmark
- CelebA-Spoof dataset
- AMSL Face Morph Image Dataset
- G. G. N S, J. Mol J, M. K. S, V. Reddy and M. T, "Biometric Spoofing Detection with Post-Quantum Cryptography Integration," ICCIDS 2026
- S. F. Bathaei, A. Torkamanpary and P. Amini, "A Comprehensive Review of Deep Learning-Based Speaker and Face Recognition in Biometric Authentication," ICSPIS 2025
- biometricupdate.com — "Post-quantum identity expands beyond cryptography" (Aug 2026)
