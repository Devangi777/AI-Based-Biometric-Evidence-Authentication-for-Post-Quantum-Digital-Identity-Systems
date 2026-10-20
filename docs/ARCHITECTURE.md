# Architecture

How a verification flows through the code, and where each security property
comes from. For the original design rationale see
[`PQ-Biometric-Auth-Spec.md`](PQ-Biometric-Auth-Spec.md); for measurements
see [`../report/FINAL_REPORT.md`](../report/FINAL_REPORT.md).

![Architecture](../report/figures/fig_a1_architecture.png)

## Verification flow

![Sequence](../report/figures/fig_a2_binding_sequence.png)

| Step | Where | What happens |
|---|---|---|
| 1. Session | `server/session_store.py` | `POST /session/start` creates a UUID, a 32-byte nonce N (`os.urandom`), a random liveness challenge C, an ML-KEM-768 keypair and an ML-DSA-65 "client identity" keypair. |
| 2. Capture | `client_demo/streamlit_app.py`, `client_demo/recorder.py` | The browser streams the camera over WebRTC; pressing **Record** captures a 4 s clip with on-video prompts (look straight, then perform challenge C). 8 evenly spaced frames are sent (the first is frontal) together with every frame's arrival timestamp. Fallback: two photos via `st.camera_input`. Local quality check: brightness and severe blur (`frame_utils.quality_check`). |
| 3. Hash | `crypto/channel.py: evidence_hash_of` | h = SHA-256 over the length-prefixed PNG bytes of every frame, i.e. exactly the bytes the server will receive. |
| 4. Sign | `POST /session/{id}/evidence` | σ = ML-DSA-65.Sign(h ‖ N ‖ ts ‖ response) (`crypto/signature.py: build_binding_payload`). Runs server-side; see README Assumption 2. |
| 5. Seal | `client_demo/api_client.py: _submit_sealed` | (ct, K) = ML-KEM-768.Encaps(pk); k = HKDF-SHA256(K, salt = N); payload sealed with AES-256-GCM, session id as associated data. Clients without liboqs use plaintext `/verify` instead. |
| 6. Open | `server/main.py: verify_evidence_sealed` | K = Decaps(sk, ct), same k, GCM open. A bad tag (tampering, wrong session) is rejected here and consumes the nonce. |
| 7. Bind | `binding/session_binding.py` + `_verify_core` | (a) σ verifies over the payload rebuilt with the **stored** nonce, (b) nonce unused, (c) \|now − ts\| ≤ 30 s, (d) challenge fulfilled (`detection/liveness_challenge.py`: digits match, or MediaPipe nose-tip moves ≥ 6% of face width), (e) SHA-256(received frames) = h. The nonce is consumed whatever the outcome. |
| 8. Detect | `detection/*.py` | Only if every check passes: the five detectors below. |
| 9. Fuse | `detection/fusion.py` | S = Σ wᵢsᵢ with w = (PAD 0.25, morph 0.20, deepfake 0.25, replay 0.15, injection 0.15). ACCEPT iff S ≥ 0.6 **and** no sᵢ < 0.5 (per-module veto). |
| 10. Explain | `server/explain.py` | Every response carries `explanations`: plain-language reasons naming the failed check or detector and the value it measured (shown under each REJECT in the dashboard). |

## Detectors

All scores are 0 (certainly attack) to 1 (certainly genuine). Each module
tries a pretrained model first and falls back, with a logged warning, to the
heuristic described here; see [`../detection/README-models.md`](../detection/README-models.md).

| Module | Signal | Catches |
|---|---|---|
| Presentation attack | Recapture cues on the face region: true-black level (weight 0.5), sharpness at a fixed face size (0.3), colour saturation (0.2) | Printed photos, screen replays (grey blacks, soft, washed out) |
| Morph | High-pass detail of the face region: ghost-peak prominence in the 2-D autocorrelation, and left/right mirror correlation | Blends of two identities (double contours, artificial symmetry) |
| Deepfake | Share of FFT energy at high spatial frequencies; minimum over video frames | GAN upsampling residue |
| Replay | 64-bit perceptual hash vs a 24 h store, confirmed by native-resolution fine-detail correlation (≥ 0.85 = same capture, scores 0); same scene but a new capture scores 0.75 | Resubmitted captures, even genuine ones, without flagging a person's second recording |
| Injection | Robust frame-interval jitter over all capture timestamps (≥ 8 intervals; exactly regular timing scores 0) + 8×8 block-boundary energy | Video files / virtual cameras, re-encoded streams |

## Security properties and where they come from

| Property | Mechanism | Test |
|---|---|---|
| Confidentiality against a future quantum computer (HNDL) | ML-KEM-768 (MLWE) + AES-256-GCM | `tests/test_channel.py`, `TestSealedChannel` |
| Integrity in transit, no cross-session reuse | GCM tag, session id as AAD | `test_tampered_ciphertext_is_rejected_at_channel`, `test_payload_sealed_for_another_session_is_rejected` |
| Evidence bound to one session and time | ML-DSA-65 over h ‖ stored N ‖ ts ‖ response; nonce single-use; 30 s window | `tests/test_binding.py`, `test_verify_rejects_reused_nonce`, `test_verify_rejects_stale_timestamp_before_detection` |
| Analysed frames are the signed frames | SHA-256(received frames) = h | `test_verify_rejects_frames_substituted_after_signing` |
| Live presence | Random challenge, verified from the frames | `tests/test_liveness_challenge.py` |
| Content genuineness | Five detectors + veto | `tests/test_detection.py`, `tests/test_fusion.py`, `scripts/demo_check.py` |
| Quantum-resistant symmetric and hash sizes | AES-256, SHA-256, HKDF-SHA256 (128-bit security under Grover) | report §4.5 |

## Configuration

Every tunable is in [`../.env.example`](../.env.example): algorithm choice
(`KEM_ALG`, `SIG_ALG` — level 5 is `ML-KEM-1024` / `ML-DSA-87`), freshness
window, per-module thresholds and weights, the fusion threshold, detection
mode, and `DEMO_MODE` (rehearsal only).
