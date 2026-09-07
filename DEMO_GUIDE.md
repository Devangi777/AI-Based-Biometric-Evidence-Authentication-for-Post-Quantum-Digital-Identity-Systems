# Demo Guide

Exact steps to run and present the live demo on Windows. Assumes SETUP.md's
split architecture (Docker server + native Streamlit client) is already
working - run through SETUP.md's verification steps at least once *before*
demo day, not for the first time in front of an audience.

## Before the audience arrives (10 minutes)

1. **Start the server:**
   ```powershell
   docker compose up --build
   ```
   Wait for the `liboqs OK: <version>` line in the build log, then confirm:
   ```powershell
   curl http://localhost:8000/health
   ```
   Expect `"status": "ok"` and `"liboqs_ready": true`. If you see
   `"status": "degraded"`, stop and fix it now (see SETUP.md
   Troubleshooting) - don't discover this mid-demo.

2. **Prepare the attack samples**, if not already present:
   ```powershell
   dir demo_assets\attacks
   ```
   Each of the 6 files listed in `demo_assets/README-assets.md` should be
   there (they're gitignored, so a fresh checkout won't have them - generate
   or capture them once per SETUP.md/README-assets.md, well before demo day,
   not live).

3. **Start the Streamlit client** in a native Windows terminal:
   ```powershell
   .venv\Scripts\activate
   streamlit run client_demo\streamlit_app.py
   ```
   It should open in your browser automatically. Confirm the sidebar shows
   "Server reachable" in green.

4. **Do one dry-run pass** of both tabs (one live capture, one simulated
   attack) so the webcam permission prompt and first-request JIT/model-load
   latency don't happen live in front of the audience.

## Part 1 - Live Capture (legitimate user flow), ~3 minutes

**What to say:** "This is the legitimate path: a real person, live, on
camera, right now. Watch what has to happen before this is accepted."

1. Open the **Live Capture** tab.
2. Click **Start new session**. Point out the displayed session ID, the
   random nonce (base64, truncated in the UI), and the liveness challenge
   text. *"The server just generated a single-use nonce and picked a random
   challenge - turn your head, nod, or say a number. This is what stops a
   previously-recorded genuine video from being replayed later, even though
   it's 100% real footage."*
3. Perform the challenge on camera (turn your head / nod / say the number
   shown), then type what you did into the challenge-response box.
4. Click **Capture & Verify**.
5. Narrate the result panel as it appears:
   - **ACCEPT** in green.
   - **Fused score** and the **per-detector bar chart** - all five modules
     scoring toward "genuine."
   - **Latency breakdown** - point out `binding_check_ms` (crypto +
     freshness, sub-millisecond to a few ms) vs. `detection_ms` (the AI
     pipeline, the larger cost) vs. `total_ms`.
   - Expand **Transaction-binding checks** - all four (signature, nonce,
     timestamp, challenge) show `true`.
6. *"Note the caption below the chart if it says some modules are running in
   mock mode - that means no pretrained checkpoint is loaded in this
   environment; see `detection/README-models.md`. The crypto and binding
   logic you just saw are real regardless."*

## Part 2 - Simulate Attack, ~1-2 minutes per attack type

**What to say (once, before the first one):** "Now the interesting part -
every one of these still goes through the *exact same* secure channel and
transaction-binding check as what you just saw. Post-quantum crypto alone
doesn't stop any of these; watch which stage catches each one."

Switch to the **Simulate Attack** tab for all five. Leave the
challenge-response box at its default ("done") unless a specific narrative
point calls for changing it.

### 1. Presentation attack (printed photo)

- Select **"Presentation attack (printed photo)"**, click **Run simulated
  attack**.
- **Say:** "This is a photo of a face held up to the camera - a photo of a
  photo. The crypto and transaction binding pass fine, because those don't
  look at content. Watch the `presentation_attack` bar."
- **Expect:** binding accepted; fused decision REJECT (or a visibly low
  `presentation_attack` score) - narrate whichever your calibration
  produces; either is a legitimate teaching moment (mock-mode heuristics are
  weaker than a real trained PAD model - say so if the score isn't
  decisively low, per `detection/README-models.md`).

### 2. Presentation attack (screen replay)

- Select **"Presentation attack (screen replay)"**, run it.
- **Say:** "Same idea, but the attacker plays a video on a phone or monitor
  instead of a printed photo - moiré patterns and screen glare are the
  giveaway a real PAD model looks for."

### 3. Face morphing

- Select **"Face morphing"**, run it.
- **Say:** "This is a blended image of two identities - designed to pass as
  either person's biometric. Watch the `morph` score specifically; this
  module uses facial-landmark symmetry, not a trained classifier, so it's a
  good example of a legitimate non-ML detection approach."

### 4. Deepfake

- Select **"Deepfake"**, run it.
- **Say:** "A synthetically generated or altered video. `deepfake_detector.py`
  samples multiple frames and takes the minimum score across them, so a
  fake only needs to be caught in *some* frames, not all."

### 5. Replay (resubmitted genuine capture)

- Select **"Replay (resubmitted genuine capture)"**, run it.
- **Say — this is the key one:** "This file is a byte-for-byte copy of a
  *genuine* capture we accepted earlier in this demo. No content classifier
  can tell it's fake, because it isn't fake - it's real biometric data being
  replayed. Watch the `replay` score specifically: it's not a trained model,
  it's a perceptual-hash match against everything we've seen recently. This
  is *why* the nonce/freshness mechanism from Part 1 exists as a second,
  independent line of defense."
- If the demo session's own earlier capture isn't the file loaded here,
  clarify: "In this run we're using a pre-captured stand-in file with the
  same property - see `demo_assets/README-assets.md` for how to swap in an
  actual capture from earlier in this session."

### 6. Injection (virtual camera / screen recording)

- Select **"Injection (virtual camera / screen recording)"**, run it.
- **Say:** "A fake video stream injected into the capture pipeline directly,
  bypassing the physical camera - a screen recording or virtual-camera
  source. This is the least mature detection module by design; we combine a
  frame-timing-consistency heuristic with a compression-artifact heuristic,
  and we say so explicitly in `detection/README-models.md` rather than
  overclaiming accuracy here. This is a documented, expected limitation, not
  a bug - very few public benchmarks exist for this attack type at all."

## Part 3 - Wrap-up, ~1 minute

1. Point at the **Recent verification attempts** log table at the bottom -
   every attempt from the session, both live and simulated, in one
   append-only audit trail.
2. **Closing line:** "Every one of these attacks passed through a
   quantum-resistant, cryptographically authenticated channel. Crypto
   secured the pipe; it took a transaction-binding freshness check and five
   independent AI detectors to catch what was actually flowing through it."

## If something goes wrong live

| Symptom | Fix |
|---|---|
| Sidebar shows "Server unreachable" | `docker compose ps` in another terminal; if the container isn't running, `docker compose up` again. Fall back to showing the pre-recorded dry-run screenshots/results while it restarts. |
| "Sample file not found" error | You skipped step 2 in "Before the audience arrives" - use the file uploader in the Simulate Attack tab as a live fallback with any face photo/video on hand. |
| Webcam permission denied in browser | Reload the page and accept the browser's camera permission prompt; confirm no other app (e.g. another video call) is holding the camera. |
| A detector's score looks "wrong" for the story | Say so - "this module is running in mock mode without a trained checkpoint in this environment, see detection/README-models.md" is a true, honest statement and a better answer than pretending the number is a finished result. |
