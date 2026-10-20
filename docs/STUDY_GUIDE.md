# AI-Based Biometric Evidence Authentication for Post-Quantum Digital Identity Systems

## Complete Review & Study Guide

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement & Existing Systems](#2-problem-statement--existing-systems)
3. [System Architecture](#3-system-architecture)
4. [Post-Quantum Cryptography — Why & How](#4-post-quantum-cryptography--why--how)
5. [Algorithm Deep-Dives](#5-algorithm-deep-dives)
6. [AI Detection Pipeline — All 5 Modules](#6-ai-detection-pipeline--all-5-modules)
7. [Transaction Binding & Freshness](#7-transaction-binding--freshness)
8. [Why These Algorithms — Not the Alternatives](#8-why-these-algorithms--not-the-alternatives)
9. [Defence & Finance Use Cases](#9-defence--finance-use-cases)
10. [Results & Evaluation](#10-results--evaluation)
11. [Future Scope & Implementation Path](#11-future-scope--implementation-path)
12. [Abbreviations & Terminology](#12-abbreviations--terminology)

---

## 1. Project Overview

This project is a **working prototype** that proves one central thesis: *securing the channel is not enough — you must also authenticate the evidence flowing through it.*

It combines three pillars:

1. **Post-Quantum Cryptography (PQC)** — ML-KEM-768 for key exchange and ML-DSA-65 for digital signatures, both NIST-standardized (FIPS 203 / 204), protecting against future quantum computers.
2. **AI-based Biometric Attack Detection** — five specialized detectors that verify the biometric evidence (face captures) is genuine, live, and unmanipulated.
3. **Transaction Binding & Freshness** — a cryptographic nonce + liveness challenge mechanism that ties each biometric capture to a unique session, preventing replay of even genuine data.

**Use case:** Remote identity verification (e-KYC, bank onboarding, government digital ID) where a user submits a live face capture over a network to a verification server.

**Stack:** Python 3.11, FastAPI, PyTorch, MediaPipe, liboqs (oqs-python), Streamlit, Docker.

**Team:** 3 members | **Timeline:** 5-week sprint | **Compute:** Laptop + Colab/Kaggle GPU

---

## 2. Problem Statement & Existing Systems

### Current Systems

Today's identity verification systems generally fall into two categories:

- **Crypto-only systems** (TLS, mTLS, ECDSA tokens) — secure the channel but *blindly trust* whatever biometric evidence arrives. A deepfake transmitted over TLS 1.3 is encrypted and authenticated as "from the right device" — but it's still a deepfake.
- **AI-only anti-spoofing** (liveness SDKs from iProov, FaceTec, BioID) — detect some attacks but rely on classical crypto (RSA/ECDSA) that will be broken by quantum computers. They also often lack replay/freshness binding — a genuine sample captured yesterday can sometimes be re-submitted today.

### Core Problem

> No existing system combines quantum-resistant channel security with multi-vector biometric attack detection *and* cryptographic freshness binding in a single pipeline. The three are treated as separate concerns, leaving gaps:

- **"Harvest now, decrypt later" (HNDL)** — adversaries record encrypted biometric sessions today, planning to decrypt them when quantum computers arrive (10–15 year horizon).
- **Multi-vector attacks** — a system checking only for liveness misses morphs, deepfakes, and injection attacks.
- **Replay gap** — without session-bound freshness, a genuine biometric captured once can be reused forever.

### Our Solution

A unified pipeline where quantum-resistant crypto, five-vector AI detection, and cryptographic session binding are interdependent — the detection won't run unless the binding checks pass, and the binding is secured by post-quantum signatures.

---

## 3. System Architecture

### Split Client-Server Design

- **Server** (Docker/Linux) — runs all PQC operations (liboqs), the 5 AI detectors, binding logic, and the decision engine via FastAPI on port 8000.
- **Client** (native OS) — Streamlit app with webcam access; computes SHA-256 evidence hash locally, calls the server for everything else.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT SIDE (Streamlit)                      │
│                                                                       │
│  ┌──────────────┐    ┌───────────────────┐    ┌──────────────────┐  │
│  │ Camera/Sensor │───▶│ Liveness Challenge │───▶│ Evidence Hash    │  │
│  │ Capture       │    │ (Head turn / Say   │    │ SHA-256(frames)  │  │
│  │ (Webcam/File) │    │  digits)           │    │                  │  │
│  └──────────────┘    └───────────────────┘    └────────┬─────────┘  │
│                                                         │            │
│                                                         ▼            │
│                                          ┌──────────────────────────┐│
│                                          │ ML-DSA Signature over    ││
│                                          │ hash ‖ nonce ‖ ts ‖ resp ││
│                                          └──────────────────────────┘│
└─────────────────────────────────────────────┬─────────────────────────┘
                                              │
                                 ML-KEM-768 Encrypted Channel
                                              │
┌─────────────────────────────────────────────▼──────────────────────────┐
│                          SERVER SIDE (Docker / FastAPI)                  │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │            TRANSACTION BINDING CHECKS (must ALL pass)           │   │
│  │  ┌──────────┐ ┌────────────┐ ┌──────────────┐ ┌─────────────┐ │   │
│  │  │(a) ML-DSA│ │(b) Nonce   │ │(c) Timestamp │ │(d) Challenge│ │   │
│  │  │ Verify   │ │ Single-Use │ │ ≤ 30 seconds │ │ Fulfilled   │ │   │
│  │  └──────────┘ └────────────┘ └──────────────┘ └─────────────┘ │   │
│  └──────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                      │
│                          ┌──────▼──────┐                               │
│                          │  ALL PASS?  │──── NO ──▶ REJECT             │
│                          └──────┬──────┘     (AI never runs)           │
│                                 │ YES                                  │
│                                 ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │           AI ATTACK DETECTION PIPELINE (5 modules)              │   │
│  │                                                                   │   │
│  │  ┌─────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌───────────┐ │   │
│  │  │  PAD    │ │ Morph  │ │ Deepfake │ │ Replay │ │ Injection │ │   │
│  │  │ (0.25) │ │ (0.20) │ │  (0.25)  │ │ (0.15) │ │  (0.15)   │ │   │
│  │  └────┬────┘ └───┬────┘ └────┬─────┘ └───┬────┘ └─────┬─────┘ │   │
│  │       └──────────┴───────────┴────────────┴────────────┘       │   │
│  │                          scores (0.0 – 1.0)                     │   │
│  └──────────────────────────────┬──────────────────────────────────┘   │
│                                 ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │     FUSION ENGINE — Weighted Average + Per-Module Veto           │  │
│  │     Fused score ≥ 0.6 AND no single module below threshold      │  │
│  │                     → ACCEPT or REJECT                           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                 │                                      │
│                                 ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │     Evaluation Logger (latency breakdown, CPU/mem, accuracy)     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Verification Flow (step by step)

1. Client calls `POST /session/start`. Server generates a session with a **random 32-byte nonce**, a **liveness challenge** ("Turn your head left", "Say 4917"), an ML-KEM keypair, and an ML-DSA keypair.

2. Client calls `POST /session/{id}/channel`. ML-KEM key encapsulation runs; both sides derive the same shared secret. An **AES-256-GCM channel key** is derived via HKDF-SHA256.

3. User performs the liveness challenge while capturing face frames. Client computes `evidence_hash = SHA-256(length-prefixed frame bytes)` (`crypto/channel.py: evidence_hash_of`).

4. Client calls `POST /session/{id}/evidence` with the hash, timestamp, and challenge response. Server constructs `binding_payload = hash ‖ nonce ‖ timestamp ‖ challenge_response` and signs it with **ML-DSA-65**.

5. Client sends the signature and base64-encoded frames. If the client has liboqs, it encapsulates against the session's ML-KEM public key itself and seals this payload with **AES-256-GCM** (key = HKDF-SHA256(shared secret, salt = nonce), session id as associated data) to `POST /session/{id}/verify-sealed`; otherwise it uses plaintext `POST /session/{id}/verify`. Server runs the **binding checks**: (a) ML-DSA signature valid, (b) nonce unused, (c) timestamp within 30s window, (d) challenge fulfilled, (e) the submitted frames hash to the signed `evidence_hash` (no frames swapped after signing). A sealed payload that fails GCM authentication is rejected before any of these.

6. **Short-circuit gate:** If *any* binding check fails → `REJECT` immediately. Detection never runs. (This is both a security design and a latency optimization.)

7. If binding passes → five AI detectors run on the frames: PAD, Morphing, Deepfake, Replay, Injection. Each returns a score from 0.0 (attack) to 1.0 (genuine).

8. The **Fusion Engine** computes a weighted average of the 5 scores and applies a dual gate: (1) fused score ≥ 0.6, AND (2) no single detector below its veto threshold → `ACCEPT` or `REJECT`.

### API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Health check: status, algorithms, liboqs readiness |
| `/session/start` | POST | Create new session with nonce, challenge, keypairs |
| `/session/{id}/channel` | POST | ML-KEM key encapsulation → derive channel key |
| `/session/{id}/evidence` | POST | ML-DSA sign the binding payload |
| `/session/{id}/verify-sealed` | POST | Same pipeline, payload sealed with ML-KEM-768 + AES-256-GCM (used when the client has liboqs) |
| `/session/{id}/verify` | POST | Full pipeline: binding checks → AI detection → ACCEPT/REJECT (plaintext) |
| `/session/{id}` | DELETE | Close session, free crypto resources |
| `/demo/reset-replay-store` | POST | Clear the replay memory between demo rehearsals (only with `DEMO_MODE=true`) |

---

## 4. Post-Quantum Cryptography — Why & How

### The Quantum Threat

**Shor's algorithm** on a sufficiently powerful quantum computer breaks RSA, ECDSA, and ECDH — all classical crypto used in TLS, SSH, and digital identity today. While such computers don't exist yet, adversaries are already harvesting encrypted data to decrypt later (the **"harvest now, decrypt later" / HNDL** threat). Biometric data is permanent — you can't change your face — so protecting it against future decryption is critical.

### NIST Post-Quantum Standards

In August 2024, NIST finalized three post-quantum standards. This project uses two:

| Standard | Algorithm | Based On | Purpose | Security Level |
|---|---|---|---|---|
| **FIPS 203** | ML-KEM-768 | CRYSTALS-Kyber | Key Encapsulation (replaces RSA/ECDH) | Level 3 (192-bit) |
| **FIPS 204** | ML-DSA-65 | CRYSTALS-Dilithium | Digital Signatures (replaces RSA/ECDSA) | Level 3 (192-bit) |

Both are **lattice-based**, relying on the hardness of the **Module Learning With Errors (M-LWE)** problem — no known quantum or classical algorithm can solve it efficiently.

### Library: liboqs / oqs-python

The **Open Quantum Safe (OQS)** project's `liboqs` is the reference C implementation of NIST-standardized PQC algorithms. `oqs-python` is its Python wrapper. It is imported **lazily** (inside functions, never at module top level) so that modules remain importable and testable on machines without a working liboqs build.

---

## 5. Algorithm Deep-Dives

### 5.1 ML-KEM (Module-Lattice Key Encapsulation Mechanism)

**What it does:** Establishes a shared secret between client and server without transmitting the secret itself — the quantum-safe replacement for Diffie-Hellman / RSA key exchange.

**How it works:**

1. **KeyGen:** Server generates a public/private keypair. The public key is a matrix `A` and vector `t = As + e` where `s` (secret) and `e` (small error) are sampled from a discrete Gaussian distribution. The private key is `s`.

2. **Encapsulate:** Client takes the server's public key, generates fresh randomness `r`, computes ciphertext `c = (Ar + e₁, t·r + e₂ + ⌊q/2⌉·m)` where `m` is a message encoding. Returns ciphertext + shared secret derived from `m`.

3. **Decapsulate:** Server uses private key `s` to recover `m` from the ciphertext by computing `c₂ - s·c₁` (the errors cancel out to reveal `m`). Derives the same shared secret.

**In this project:** Used at `POST /session/{id}/channel`. The raw ML-KEM shared secret (32 bytes) is passed through **HKDF-SHA256** with the domain separator `"pq-biometric-auth channel key v1"` to derive an **AES-256-GCM** channel key.

**Parameters (ML-KEM-768):**
- Public key: 1,184 bytes | Ciphertext: 1,088 bytes | Shared secret: 32 bytes
- Module dimension: k=3, n=256, q=3329

**Security property:** IND-CCA2 — tampered ciphertexts produce a random (wrong) key rather than failing visibly (implicit rejection).

### 5.2 ML-DSA (Module-Lattice Digital Signature Algorithm)

**What it does:** Produces a digital signature proving that a message was created by the private-key holder and hasn't been tampered with — the quantum-safe replacement for RSA/ECDSA signatures.

**How it works:**

1. **KeyGen:** Generate matrix `A`, secret vectors `s₁, s₂` with small coefficients. Public key is `(A, t = As₁ + s₂)`. Private key includes `s₁, s₂`.

2. **Sign:** Sample a masking vector `y`, compute `w = Ay`. Hash the high-order bits of `w` together with the message to get challenge `c`. Compute `z = y + c·s₁`. Rejection-sample: restart if `z` reveals too much about `s₁`. Signature is `(z, hint)`.

3. **Verify:** Recompute `w' = Az - ct`, check that hashing its high bits with the message reproduces `c`.

**In this project:** Used to sign the **binding payload** = `evidence_hash ‖ session_nonce ‖ timestamp ‖ challenge_response`. The server constructs the same payload independently (using its own stored nonce, not the client's) and verifies the signature.

**Parameters (ML-DSA-65):**
- Public key: 1,952 bytes | Signature: 3,309 bytes
- Module dimensions: k=6, l=5, n=256, q=8380417

### 5.3 HKDF-SHA256 (Key Derivation)

**Purpose:** The raw ML-KEM shared secret is cryptographically strong but not domain-specific. HKDF (HMAC-based Key Derivation Function, RFC 5869) extracts and expands it into a purpose-specific **AES-256-GCM key** with a domain separation string to prevent cross-protocol attacks.

**Steps:**
1. **Extract:** `PRK = HMAC-SHA256(salt="", shared_secret)`
2. **Expand:** `key = HMAC-SHA256(PRK, info="pq-biometric-auth channel key v1" ‖ 0x01)`, truncated to 32 bytes

### 5.4 SHA-256 (Evidence Hashing)

Standard cryptographic hash producing a 256-bit fixed-length digest of the biometric frames. Used client-side to create the `evidence_hash` included in the binding payload. SHA-256 is **quantum-resistant** for pre-image resistance (Grover's algorithm only halves the effective security to 128 bits, still considered safe).

### 5.5 Classical Baseline (for comparison only)

To measure PQC overhead, the project implements the same operations with classical algorithms:

- **RSA-3072 + OAEP** — key exchange analog (encrypt/decrypt a random shared secret)
- **ECDSA P-256 + SHA-256** — digital signature analog

These are **NOT used in the production pipeline**. They exist solely in `crypto/classical_baseline.py` for the evaluation benchmark that compares PQC vs. classical latency and payload sizes.

### 5.6 Meso4 (Deepfake Detection CNN)

**Architecture:** A lightweight CNN from Afchar et al. (2018) designed specifically for detecting face manipulations at the mesoscopic level (between pixel-level artifacts and high-level semantics).

- 4 convolutional blocks: Conv2d → BatchNorm → LeakyReLU(0.1) → MaxPool2d → Dropout(0.5)
- Filter progression: 3→8 (3×3), 8→8 (5×5), 8→16 (5×5), 16→16 (5×5)
- Dense head: Flatten → Linear(16×8×8, 16) → LeakyReLU → Dropout → Linear(16, 2)
- Input: 256×256 RGB. Output: 2-class softmax (genuine / fake)

**Why Meso4:** CPU-friendly (no GPU needed at inference), well-studied baseline, fast training on limited GPU hours.

### 5.7 Perceptual Hashing (pHash) — Replay Detection

A 64-bit hash computed from the structural content of an image (DCT-based), robust to minor compression/scaling changes. Two images are "similar" if their Hamming distance is below a threshold (default: 8 bits).

- Not a classifier — a **database lookup**. Every submitted frame's pHash is stored; if a new submission matches within the threshold and within the 24-hour time window, it's flagged as a replay.
- This is the **only detector that is fully functional** (not in mock mode) without any model download.

---

## 6. AI Detection Pipeline — All 5 Modules

Every detector follows the same contract: score from **0.0** (certainly attack) to **1.0** (certainly genuine). Each tries pretrained model first, falls back to a documented mock heuristic if unavailable.

| Module | Attack Type | Pretrained Model | Mock Heuristic | Key Signal |
|---|---|---|---|---|
| **PAD** | Photo, screen replay, mask | MiniFASNet | True-black level + sharpness + saturation of the face region | Paper and screens can't show true black; recaptures are soft and washed out |
| **Morph** | Blended identity images | N/A — signal-processing detector (MediaPipe only crops the face) | Ghosting + mirror-symmetry of high-pass detail | Pixel-averaging two identities leaves double contours and unnaturally symmetric fine texture |
| **Deepfake** | GAN-generated / face-swapped video | Meso4 CNN (Afchar 2018) | 2D FFT high-frequency energy ratio | GAN upsampling leaves spectral fingerprints (Frank 2020) |
| **Replay** | Resubmitted genuine sample | N/A — pHash store + fine-detail fingerprint, always functional | N/A | Same capture = pHash ≤ 8 bits **and** native-resolution detail correlation ≥ 0.85 (scores 0); a new recording of the same scene scores 0.75 and never vetoes |
| **Injection** | Virtual camera / injected stream | Planned CNN (not yet implemented) | Robust frame-timing jitter over all capture timestamps + 8×8 block-boundary compression artifacts | File/virtual-camera streams have machine-perfect timing; re-encoding leaves block edges |

### Mock Heuristic Details

**PAD Mock:** Three recapture cues measured on the face region (MediaPipe box + 20%, or the central crop):
- True-black level (weight 0.5): 1st-percentile luminance. A live face has pupils/hair near 0; paper and screens can't render black. Live webcam frames measured 0–2, recaptures 50–62. Score ramps from 40 (attack) to 15 (live).
- Sharpness (0.3): Laplacian variance at a fixed 160 px face width, log-scaled from 8 to 25. Live webcam faces 26–109, printed photo 7.
- Saturation (0.2): mean HSV saturation, 45 → 75. Kept low-weight because it depends on skin tone and lighting.
- An earlier version used whole-frame sharpness / 500, which only a sharp still photo reaches, so every real webcam frame (15–50) was rejected.

**Morph detector:** Works on the face region (MediaPipe Face Mesh box + 20% margin, or the central 60% of the frame without MediaPipe), on its high-pass detail (image minus Gaussian blur σ=2). Two signals:
- *Ghosting:* the most prominent secondary peak of the 2-D autocorrelation at offsets of 4–15% of the face width. A double exposure of two misaligned faces creates a sharp peak at their offset. Penalty ramps from 0.13 to 0.22.
- *Artificial symmetry:* correlation of the detail with its left/right mirror image. Real faces ≈ 0.03, a blend with a mirrored identity ≈ 0.99. Penalty ramps from 0.20 to 0.50.
- Score = `1 − max(ghost_penalty, mirror_penalty)`. (Landmark asymmetry is reported for information only: it measured 0.03–0.045 for both genuine faces and morphs, so it cannot discriminate.)

**Deepfake Mock:** High-frequency energy ratio in 2D FFT spectrum. GAN upsampling leaves high-frequency artifacts. Score = `clip(1.0 - (high_freq_ratio - 0.35) / 0.25)`. For video, takes minimum score across sampled frames.

**Injection Mock:** Two signals:
- Frame-timing jitter = 1.4826 × MAD / median of the frame intervals (robust to a few late frames), computed over every capture timestamp and only when there are ≥ 8 intervals. Exactly regular timestamps — synthesised from a video file's nominal fps, as a virtual camera does — score 0; very erratic timing scores low. Score = `clip(min((jitter − 0.002)/0.018, 1 − (jitter − 0.35)/0.65))`
- 8×8 block-boundary energy (re-encoding elevates block-edge gradients). Score = `clip(1.0 - (block_ratio - 1.1) / 1.5)`
- Combined: `0.65 × timing + 0.35 × compression`

### Fusion Engine

The decision engine uses **weighted-average fusion with per-module veto**:

- **Weights:** PAD = 0.25, Deepfake = 0.25, Morph = 0.20, Replay = 0.15, Injection = 0.15
- **Accept threshold:** 0.6
- **Dual gate:** ACCEPT only if (1) weighted average ≥ 0.6 *AND* (2) no single module below its individual threshold
- **Single-module veto:** even if the average is 0.9, a replay score of 0.0 triggers REJECT

---

## 7. Transaction Binding & Freshness

This is the **novel integration point** of the project — what makes it more than "crypto + AI side by side."

### The Four Binding Checks

| Check | What it verifies | What it prevents |
|---|---|---|
| (a) ML-DSA Signature | Payload not tampered with | Evidence substitution, man-in-the-middle |
| (b) Nonce Single-Use | This exact nonce hasn't been used before | Replay of same session's evidence |
| (c) Timestamp Freshness | Captured within 30 seconds of now | Stale / pre-recorded evidence |
| (d) Challenge Fulfilment | User performed the liveness action | Pre-recorded video without correct challenge response |

**Key design:** The nonce is marked as used after *every* verify attempt regardless of outcome. A failed submission cannot be retried on the same nonce — the client must start a new session.

### Liveness Challenges

- "Turn your head slightly left/right" — verified via MediaPipe nose-tip displacement across frames
- "Nod your head once" — same nose-tip displacement check
- "Say the number XXXX" — currently regex digit matching only (no actual ASR — documented limitation)

---

## 8. Why These Algorithms — Not the Alternatives

### PQC Algorithm Alternatives

| Category | We Chose | Alternative | Why Not |
|---|---|---|---|
| Key Exchange | **ML-KEM** (lattice) | BIKE, Classic McEliece, HQC (code-based) | McEliece has ~260 KB public keys (impractical for mobile/IoT). BIKE/HQC are under NIST Round 4, not yet standardized. |
| Key Exchange | **ML-KEM** | SIKE/SIDH (isogeny-based) | **Broken in 2022** by Castryck-Decru attack. Completely insecure. |
| Signatures | **ML-DSA** (lattice) | FALCON (lattice, NTRU-based) | FALCON produces smaller signatures but requires careful constant-time floating-point arithmetic — harder to implement safely. |
| Signatures | **ML-DSA** | SLH-DSA / SPHINCS+ (hash-based) | SPHINCS+ is conservative but signatures are ~8–50 KB vs. ML-DSA's ~3.3 KB. Too large for per-frame signing. |
| Signatures | **ML-DSA** | RSA / ECDSA (classical) | Vulnerable to Shor's algorithm. The whole point of this project. |

### AI Model Alternatives

| Detector | We Chose | Alternative | Why Not |
|---|---|---|---|
| Deepfake | **Meso4** | XceptionNet, EfficientNet-B4 | More accurate but require GPU inference. Meso4 is CPU-friendly and trainable within sprint's GPU budget. |
| PAD | **MiniFASNet** | FAS-SGTD, CDCN | MiniFASNet is purpose-built, CPU-friendly, publicly available. |
| Morph | **Ghosting + mirror-symmetry of fine detail** | MorphGAN discriminator, MixFaceNet | Feature-based needs no training data or GPU. Morphing datasets require weeks-long access approval. |
| Replay | **pHash store** | Classifier on sensor noise patterns | Replay attacks resubmit genuine data — a content classifier can't catch them. Only session/freshness binding works. |

---

## 9. Defence & Finance Use Cases

### Primary Use Case (This Project)

**Remote identity verification (e-KYC)** — onboarding for banks, government digital IDs, border control e-gates. A user submits a live face capture over the network; the system verifies it is genuine, live, unmanipulated, and freshly captured, over a quantum-resistant channel.

### Defence Applications

- **Battlefield biometric identification:** Soldiers use handheld devices to verify the identity of persons of interest. PQC ensures captured biometrics can't be decrypted even if the device is captured and the adversary gains future quantum capability.
- **Secure facility access:** Multi-factor biometric + PQC authentication for access to classified facilities, data centers, or nuclear installations.
- **Intelligence asset verification:** Remote identity verification of field operatives via secure video link, with deepfake/morph detection preventing adversary impersonation.
- **Defence supply chain:** Biometric authentication at critical checkpoints (ammunition, sensitive technology), preventing insider threats via spoofed identities.
- **UAV/drone operator verification:** Continuous biometric authentication of drone operators to prevent unauthorized takeover.

### Financial Services Applications

- **High-value transaction authorization:** For wire transfers above a threshold, require live biometric verification with PQC binding — preventing deepfake-authorized transfers (a real and growing fraud vector).
- **Remote account opening (KYC/AML):** Comply with RBI/SEBI/FATF guidelines for video KYC while ensuring the video isn't morphed or injected.
- **Trading floor access:** Biometric + PQC authentication for algorithmic trading systems, preventing unauthorized access that could trigger market-moving trades.
- **Insurance fraud prevention:** Verify claimant identity during video interviews, detecting deepfake impersonation of policy holders.
- **Cryptocurrency custody:** Multi-factor biometric gates for cold wallet access, with quantum-resistant signatures ensuring the authorization can't be forged even decades later.
- **Cross-border payment authentication:** SWIFT-like networks adopting PQC for message authentication; biometric layer prevents authorized-user impersonation.

---

## 10. Results & Evaluation

> Measured results (latency, PQC vs classical, the 12-scenario attack matrix and the quantum-circuit experiments) are in `report/FINAL_REPORT.md` §4.4; `python scripts/demo_check.py` reproduces the attack matrix against a running server.

### What is Measured

| Metric | How Measured | Expected Outcome |
|---|---|---|
| Detection Accuracy | Per-module accuracy, precision, recall, F1 on test splits | Mock heuristics: moderate; real models: significantly better |
| APCER | Fraction of ATTACK samples wrongly accepted as genuine | Lower is better (false accept rate) |
| BPCER | Fraction of GENUINE samples wrongly rejected | Lower is better (false reject rate) |
| PQC vs. Classical Latency | ML-KEM encap/decap vs. RSA-3072; ML-DSA sign/verify vs. ECDSA-P256 | ML-KEM faster than RSA-3072; ML-DSA comparable to ECDSA |
| Payload Size | Public key + ciphertext/signature sizes | PQC keys larger (~1.2 KB vs. ~32 B for ECDH) but practical |
| End-to-End Latency | `time.perf_counter()` from submission to decision, broken down by stage | Sub-second mock; 2–5 seconds with real models |
| Throughput | Concurrent sessions/second via `httpx` load generator | Measured at various concurrency levels |
| CPU/Memory | `psutil` snapshots during crypto and detection | PQC overhead negligible vs. AI inference |

### How to Run

```bash
# Start server
docker compose up --build

# Run benchmark
python -m evaluation.benchmark

# Run tests
pytest tests/
```

**Output:** CSVs + matplotlib charts in `evaluation/results/`:
- Bar charts: per-stage latency breakdown
- Line charts: throughput vs. concurrency
- Tables: accuracy per attack type

### Key Insight

The PQC overhead is a small fraction of the total pipeline cost. The AI detection stage dominates latency. This means adopting post-quantum security is essentially "free" relative to the AI processing that's already needed.

---

## 11. Future Scope & Implementation Path

| Enhancement | What | How to Implement |
|---|---|---|
| **Hybrid PQC** | X25519 + ML-KEM-768 hybrid key exchange | Use liboqs's hybrid KEM support; combine ECDH + ML-KEM shared secrets via dual HKDF. Protects against PQC algorithm flaws. |
| **Separate client device** | ML-DSA signing on the actual client | `crypto/kem.py` and `crypto/signature.py` are already device-agnostic. Deploy liboqs on mobile SDK or WASM. |
| **Real pretrained models** | Replace mock heuristics with trained checkpoints | Download weights per `detection/README-models.md`. Fine-tune on FaceForensics++ (deepfake), CelebA-Spoof (PAD), AMSL (morph). |
| **Learned fusion** | Replace weighted average with trained classifier | Logistic regression or small MLP over 5 scores + metadata. |
| **Multi-modal biometrics** | Add iris, fingerprint, voice alongside face | Each modality gets its own pipeline; fusion expands. Same binding mechanism applies. |
| **Hardware Security Module** | Store ML-DSA keys in HSM/TEE | PKCS#11 interface; key never leaves secure enclave. Critical for defence/finance. |
| **Federated learning** | Train detectors without centralizing biometric data | Each institution trains locally, shares only gradients. Preserves privacy. |
| **Blockchain audit trail** | Immutable verification decision record | Hash decision + PQC signature onto permissioned ledger for non-repudiation. |
| **Real-time ASR** | Actual speech recognition for voice challenges | Integrate Whisper or Vosk for "Say the number" challenges. |

---

## 12. Abbreviations & Terminology

| Term | Definition |
|---|---|
| **PQC** | Post-Quantum Cryptography — algorithms designed to resist both classical and quantum attacks |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism — FIPS 203, quantum-safe key exchange (from CRYSTALS-Kyber) |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm — FIPS 204, quantum-safe signatures (from CRYSTALS-Dilithium) |
| **KEM** | Key Encapsulation Mechanism — securely establishing a shared secret between two parties |
| **M-LWE** | Module Learning With Errors — the hard mathematical problem underlying ML-KEM and ML-DSA |
| **HKDF** | HMAC-based Key Derivation Function — derives strong keys from a shared secret (RFC 5869) |
| **AES-256-GCM** | Advanced Encryption Standard (256-bit) in Galois/Counter Mode — authenticated encryption |
| **SHA-256** | Secure Hash Algorithm, 256-bit digest — used for evidence hashing |
| **RSA-3072** | Rivest-Shamir-Adleman (3072-bit key) — classical encryption, used as benchmark baseline only |
| **ECDSA P-256** | Elliptic Curve Digital Signature Algorithm on NIST P-256 — classical signatures, baseline only |
| **OAEP** | Optimal Asymmetric Encryption Padding — padding scheme for RSA encryption |
| **PAD** | Presentation Attack Detection — detecting photo/screen/mask spoofing |
| **APCER** | Attack Presentation Classification Error Rate — false accept rate for attacks |
| **BPCER** | Bona-fide Presentation Classification Error Rate — false reject rate for genuine users |
| **pHash** | Perceptual Hash — 64-bit content-based hash robust to minor image changes |
| **FFT** | Fast Fourier Transform — spatial-to-frequency domain conversion for detecting GAN artifacts |
| **DCT** | Discrete Cosine Transform — used in JPEG compression and perceptual hashing |
| **CNN** | Convolutional Neural Network — deep learning architecture for image analysis |
| **GAN** | Generative Adversarial Network — ML architecture used to generate deepfakes |
| **Meso4** | Lightweight 4-block CNN for face manipulation detection (Afchar et al. 2018) |
| **MiniFASNet** | Mini Face Anti-Spoofing Network — CPU-friendly liveness detection model |
| **MediaPipe** | Google's ML framework for face detection/landmark extraction (468-point Face Mesh) |
| **e-KYC** | Electronic Know Your Customer — remote digital identity verification |
| **HNDL** | Harvest Now, Decrypt Later — recording encrypted data today for future quantum decryption |
| **Shor's Algorithm** | Quantum algorithm breaking RSA/ECDSA/ECDH in polynomial time |
| **Grover's Algorithm** | Quantum search algorithm halving symmetric-key/hash security |
| **IND-CCA2** | Indistinguishability under Adaptive Chosen-Ciphertext Attack — ML-KEM's security guarantee |
| **Nonce** | Number used once — 32-byte random value ensuring each verification is unique |
| **FIPS** | Federal Information Processing Standards — US government crypto standards |
| **liboqs** | Open Quantum Safe C library for NIST PQC algorithms; used via `oqs-python` |
| **HSM** | Hardware Security Module — tamper-resistant hardware for key storage |
| **TEE** | Trusted Execution Environment — secure processor enclave |
| **TLS** | Transport Layer Security — standard encrypted internet communication protocol |
| **ISO/IEC 30107-3** | International standard defining APCER/BPCER metrics for PAD evaluation |
| **CRYSTALS** | Cryptographic Suite for Algebraic Lattices — the research project behind Kyber and Dilithium |
| **NTRU** | Number Theory Research Unit — an older lattice-based crypto scheme (FALCON is NTRU-based) |
| **SIDH/SIKE** | Supersingular Isogeny DH/KE — broken PQC candidate (Castryck-Decru 2022) |
| **SPHINCS+** | Stateless hash-based signature scheme — conservative but very large signatures |
| **AML** | Anti-Money Laundering — regulatory framework for financial crime prevention |
| **FATF** | Financial Action Task Force — international AML/KYC standard body |

---

*Study guide prepared from project source code and specification. For hands-on review, run `pytest tests/` and `python -m evaluation.benchmark`.*
