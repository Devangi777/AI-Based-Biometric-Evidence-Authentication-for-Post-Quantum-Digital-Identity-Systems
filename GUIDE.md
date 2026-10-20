# Presenter's Guide

Your hands-on guide: how the system works, how to run it on your Mac, and
exactly what to click to show an **ACCEPT** and every kind of **REJECT**,
with what you'll see on screen and what to say. (The public overview is in
[`README.md`](README.md); the full write-up is in
[`report/FINAL_REPORT.md`](report/FINAL_REPORT.md).)

---

## 1. How it works, in plain words

A person proves who they are by showing their face to a camera. The system
has to answer two questions:

1. **Did this evidence arrive safely, and does it belong to *this* session?**
   That's the job of the cryptography.
2. **Is the face in it real, live and unaltered?** That's the job of the AI checks.

One verification goes through these steps:

| Step | What happens | Why |
|---|---|---|
| Session | The server issues a one-time code (nonce) and a random task: "turn your head left", "nod", or "say the number 4821". | A recording made earlier can't contain a task chosen just now. |
| Capture | You record 4 s: look straight at the camera, then do the task. | The movement proves a live person. |
| Fingerprint and signature | The frames get a SHA-256 fingerprint, which is signed with **ML-DSA-65** together with the one-time code, the time and your answer. | Ties *this* evidence to *this* session and moment. |
| Sealed channel | The client sets up a key with **ML-KEM-768** and encrypts everything with **AES-256-GCM**. | Quantum computers can't break it later ("harvest now, decrypt later"). |
| Binding gate | The server checks: decrypts and authenticates? signature valid? code unused? less than 30 s old? task done? frames match the fingerprint? | Any failure → **REJECT in about 1 ms, before any AI runs.** |
| AI checks | Five detectors score the evidence from 0 (attack) to 1 (genuine). | Catches fakes that the cryptography can't see. |
| Decision | ACCEPT only if the weighted score is at least 0.6 **and** no detector is below 0.5 (a single detector can veto). | An attack can't hide inside an average. |
| Explanation | Every REJECT comes with plain-language reasons and the measured values. | You (and the audience) can see *why*. |

**What each detector looks for:**

| Detector | Looks for | Genuine | Attack |
|---|---|---|---|
| Presentation attack (PAD) | Photo or screen held to the camera: are the darkest parts truly black? Is the face sharp? Are the colours rich? | Pupils and hair near black; sharp; saturated | Grey blacks (paper and screens can't show black), soft, washed out |
| Morph | Two faces blended: a faint double outline ("ghost"), or unnaturally mirror-symmetric skin texture | No ghost, natural asymmetry | Ghosted edges |
| Deepfake | Excess very-fine-detail energy, left by AI generators when they upscale | ≤ ~35% of energy in fine detail | Much more |
| Replay | Has the server seen *this exact capture* before? Same picture **and** same pixel-level detail | A new recording, even of the same person in the same place | A resent copy |
| Injection | A video fed in instead of a camera: frame timing too perfect, re-encoding blocks | Natural timing jitter | Machine-perfect timing, heavy compression |

**The quantum part:** we simulated, in Qiskit, the quantum algorithms that
force this design. **Shor's algorithm** factors 15 (and would break RSA and
elliptic curves), which is why we use ML-KEM and ML-DSA. **Grover's
algorithm** speeds up key search, which is why we use 256-bit AES and SHA-256.
A **quantum random number generator** is proposed for the one-time codes.
Figures are in `report/figures/` (`fig_q*`).

---

## 2. Running it on your Mac

### Option A: natively (recommended for the demo)

```bash
cd AI-Based-Biometric-Evidence-Authentication-for-Post-Quantum-Digital-Identity-Systems

./scripts/run_server.sh        # terminal 1: the server on :8000
./scripts/run_client.sh        # terminal 2: the dashboard, opens http://localhost:8501
```

These scripts always use the project's `.venv`, so they work even if you
forgot to activate it. **Don't type plain `uvicorn ...`** unless `.venv` is
active: otherwise your Mac runs a different Python (3.13) that doesn't have
the project's packages and fails with `ModuleNotFoundError: No module named
'imagehash'`. Worse, its reload supervisor can stay alive holding port 8000
and block the next start. If that happens: `lsof -iTCP:8000 -sTCP:LISTEN`
shows the PID; `kill <PID>`.

Your `.env` has `DEMO_MODE=true`, which enables the **Reset replay memory**
button. The server takes 10–30 s to start, while MediaPipe loads; wait for
`Application startup complete`.

### Option B: server in Docker

```bash
docker compose up --build -d          # server on :8000; first build compiles liboqs
docker compose logs -f server         # watch it start
streamlit run client_demo/streamlit_app.py
```

To make Docker pick up `.env` changes (like `DEMO_MODE`), run
`docker compose up -d --force-recreate`. Never run the native server and
Docker at the same time: both use port 8000, and requests land on either one
at random.

> ⚠️ **Disk space.** Docker Desktop keeps its whole VM in one growing file. When
> your Mac's disk is nearly full, the container fails with
> `input/output error` and turns *unhealthy*; this has already happened once
> on this machine. Keep at least 10 GB free, then quit and reopen Docker
> Desktop. Or simply use Option A, which doesn't need Docker.

### First time on a new machine

```bash
pip install scikit-image && python scripts/make_demo_assets.py   # builds demo_assets/attacks/
```

---

## 3. Ten minutes before the demo

1. Start the server and wait for `Application startup complete`.
2. Run the self-check:
   ```bash
   python scripts/demo_check.py --explain
   ```
   It must end with **`12/12 scenarios behaved as expected`**. It also clears
   the replay memory, so the genuine sample counts as new.
3. Start the dashboard. The sidebar must show **Server online** and
   **Client channel: sealed**.
4. **Rehearse one live recording** in the room's lighting (section 5).
5. Click **Reset replay memory** in the sidebar.

---

## 4. Dashboard tour

- **Sidebar:** server status, the channel mode (*sealed* = ML-KEM + AES-GCM
  on this laptop), and **Reset replay memory**.
- **Live Capture tab:** a real person, recorded.
- **Simulate Attack tab:** pre-made fake samples, or upload your own.
- **Tamper with Protocol tab:** a genuine capture, but with the protocol attacked.
- **Result panel** (after every run):
  - Banner: **✅ ACCEPT**, or **❌ REJECT** with the stage that stopped it.
  - **Why was this rejected?**: one bullet per reason, with the measured values.
  - Three columns: **1 · Post-quantum channel**, **2 · Transaction binding**
    (✅/❌ per check), **3 · AI evidence checks** (score and verdict per
    detector, plus the combined score).
  - Timing line, and **Raw server response** (everything, as JSON).
- **Verification log** at the bottom: every attempt, its decision and what decided it.

---

## 5. How to show ACCEPT

### A real person (the strongest demo)

1. **Live Capture** → **Start new session**. Read the challenge out loud.
2. Press **START** on the video box and allow camera access. Your live video appears.
3. Press **⏺ Record 4 s clip**. The video gets a red **● REC** bar:
   - first ~1 s: *"Look straight at the camera"*: do that;
   - then *"Now: turn your head slightly left"* (or nod): do it clearly.
4. A strip of 8 recorded frames appears. For a "say the number" challenge,
   type the number.
5. Press **Verify** → **✅ ACCEPT**. The five binding checks are all ✅, and
   all five detectors say "genuine".

> *"The photo was encrypted on this laptop with a quantum-safe key exchange; the signature ties this
> recording to this session for 30 seconds; and all five AI checks agree it's a live, unaltered face."*

Tips: light your face from the front (not a window behind you), keep your
whole face in the frame, and make the movement clearly. You can record again
straight away. A second recording of you is **not** treated as a replay,
because it's a new capture.

### The genuine sample (backup)

**Simulate Attack** → *Genuine sample (bona fide control)* → **Submit sample** → **✅ ACCEPT**.
It works once per server run; after that it *is* a replay (see below).
Reset the replay memory to show it again.

---

## 6. How to show REJECT

### Fakes: **Simulate Attack** tab

Run these in this order, starting with the genuine sample. Each goes through
the same encryption and binding as a live capture. The attacker is assumed to
know the challenge, so it's the AI that must catch the fake.

| Select | Result | The explanation says (roughly) | What to say |
|---|---|---|---|
| Genuine sample | ✅ ACCEPT | "Every check passed…" | "A genuine capture." |
| Replay (resubmitted genuine capture) | ❌ Replay 0.00 | Same capture: hash difference 0 bits, fine detail matches 1.00 | "Byte-for-byte the photo we just accepted, on a fresh session with a valid signature. The server remembers it." |
| Presentation attack (printed photo) | ❌ PAD ≈ 0.01 | Grey blacks (62/255), soft (sharpness 7), washed out (saturation 47) | "Paper can't show true black, and a live face always has some." |
| Presentation attack (screen replay) | ❌ PAD ≈ 0.41, Morph 0.00, Injection ≈ 0.20 | Grey blacks; repeating moiré pattern; video timing | "A phone screen held up: grey blacks plus the screen's pixel grid." |
| Face morphing | ❌ Morph 0.00 | A faint second outline of the face (ghosting) | "Two faces blended to pass as either person." |
| Deepfake | ❌ Deepfake ≈ 0.2, Injection ≈ 0.35 | Too much fine-detail energy; machine-perfect timing | "AI-generated faces leave high-frequency residue." |
| Injection (virtual camera) | ❌ Injection ≈ 0.21 | Machine-perfect frame timing; re-encoding blocks | "A video fed in instead of a camera." |

Point at the combined score: for five of the six fakes it is **above 0.6** (0.65–0.85).
*"An average would have accepted it. One detector that is sure it's an attack can veto."*

### Protocol attacks: **Tamper with Protocol** tab

All use the *genuine* sample, so no AI could object to the content. Every
one is rejected in about **1 ms**, and the AI column says *"Not run"*.

| Select | Rejected by | The explanation says |
|---|---|---|
| Different frames submitted than the ones that were signed | Frames match the signed hash ❌ | "…the evidence was swapped after signing." |
| One bit flipped in the sealed payload in transit | Channel ❌ | "…failed its integrity check (AES-256-GCM tag)…" |
| Evidence signed 2 minutes ago | Timestamp fresh ❌ | "…captured 120 s before it reached the server…" |
| Second submission on an already-used session nonce | Nonce unused ❌ | "This session's one-time code was already used…" |
| Wrong answer to the liveness challenge | Challenge ❌ | "…the number given (0000) is not the one requested…" (number challenge), or "…no response to the challenge was given" (movement challenge) |

### Rejecting a *live* attempt (optional, unscripted)

- **Don't move during the recording** → ❌ *"…the head moved only 0% of the
  face width (at least 6% is needed)…"*
- **"Say the number" with a wrong number** → ❌ challenge not met.
- **Upload a file** (Simulate Attack → upload): a phone photo of a printed
  picture, or a screen recording. Results vary with the material: these are
  heuristic detectors, not trained models, so rehearse before showing it.

---

## 7. A 12-minute running order

| Min | Show | File / tab |
|---|---|---|
| 0–1 | The problem and the idea | `report/figures/fig_a1_architecture.png` |
| 1–3 | Live ACCEPT | Live Capture |
| 3–7 | Fakes REJECT | Simulate Attack (table in §6) |
| 7–9 | Protocol attacks REJECT | Tamper with Protocol |
| 9–11 | Quantum circuits and noise | `fig_q1`/`fig_q4` (Shor), `fig_q2`/`fig_q5` (Grover), `fig_q6` (noise sweep) |
| 11–12 | Numbers and the log | Verification log; README results table |

Numbers worth quoting: ML-KEM is **48× faster** than RSA-3072; the whole
post-quantum path costs **0.88 ms** (**1.9%** of server time); protocol
attacks are rejected in about **1 ms**; Shor succeeds **0.50 → 0.13** and
Grover **0.96 → 0.43** at 1% gate error.

---

## 8. Questions to expect

- **"Is anything here actually quantum?"** The cryptography is
  *post-quantum* (lattice-based, runs on normal computers). The quantum
  computing part is the threat model: Shor, Grover and a QRNG, implemented
  and simulated in Qiskit, with and without noise.
- **"Are the detectors trained models?"** No. They are signal-processing
  checks with documented paths to pretrained models (MiniFASNet, Meso4). The
  demo shows each layer working; dataset accuracy would need
  FaceForensics++ / CelebA-Spoof.
- **"Why is the deepfake video also flagged as injection?"** It's a
  pre-recorded file: its frame timing is perfectly regular, which a live
  camera never produces.
- **"Why isn't my second recording a replay?"** Replay means *the same
  capture* sent again. A new recording has fresh sensor noise and is never
  pixel-aligned with the last one.
- **"Who signs the evidence?"** In this prototype the ML-DSA "client
  identity" lives in the server process; the encryption is done by the client.

---

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| Live capture rejected: **PAD** | Read the explanation. *Grey blacks* → light from the front, no bright window behind. *Soft* → hold still, clean the lens, move a little closer. |
| Live capture rejected: **challenge** | Make the movement bigger, after the prompt changes to "Now: …". |
| Live capture rejected: **replay** | You submitted a saved image twice. Record a new clip. |
| Live capture rejected: **morph** | A strong repeating pattern behind your face (stripes, blinds); use a plain background. |
| No **Record** button | Press **START** on the video box and allow the camera. In System Settings → Privacy & Security → Camera, allow your browser. |
| Video box never connects | Use the **"Camera stream won't connect? Use two photos instead"** fallback just below it. |
| Sidebar: *Server unreachable* | Start the server with `./scripts/run_server.sh`; give it up to 30 s. |
| `ModuleNotFoundError: No module named ...` when starting | You ran plain `uvicorn` outside `.venv` (wrong Python). Use `./scripts/run_server.sh`. |
| `address already in use` on port 8000 | A leftover server holds it: `lsof -iTCP:8000 -sTCP:LISTEN`, then `kill <PID>`; or `docker compose down` if it's the container. |
| Sidebar: *Client channel: plaintext* | Run Streamlit from the project `.venv` (it has liboqs). |
| Genuine sample rejected as replay | It was already used; **Reset replay memory**. |
| "Refused" on Reset | `DEMO_MODE=true` in `.env`, then restart the server (Docker: `--force-recreate`). |
| Docker container *unhealthy* / `input/output error` | The Mac's disk is full: free space, restart Docker Desktop, or run natively. |
| Odd results that differ from the self-check | Two servers on port 8000 (native and Docker); stop one. |

---

## 10. Command cheat-sheet

```bash
source .venv/bin/activate
./scripts/run_server.sh                             # server (always uses .venv)
./scripts/run_client.sh                             # dashboard
python scripts/demo_check.py --explain              # 12-scenario self-check with reasons
python scripts/make_demo_assets.py                  # rebuild attack samples
pytest tests/ -q                                    # 105 tests
curl http://localhost:8000/health                   # server status
docker compose up --build -d / logs -f server / down
```
