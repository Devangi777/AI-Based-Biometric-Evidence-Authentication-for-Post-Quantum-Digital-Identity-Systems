# Demo attack samples

These are **demo-scale substitutes** for the "Simulate Attack" panel in
`client_demo/streamlit_app.py` (spec Section 12) - small, self-generated
files that exercise the same code path as a live capture, so the audience
sees each attack type actually get caught (or not) by the real pipeline.
They are **not** the full research datasets used for the Section 8
evaluation numbers - see `datasets/download_samples.md` for what those would
add.

None of these files are committed to the repo (`.gitignore` excludes
`demo_assets/attacks/*.jpg|.mp4|...`) - each team member generates their own
locally before presenting, per the instructions below. `client_demo/`'s
"Simulate Attack" dropdown also accepts an upload if you'd rather bring your
own file on demo day.

| File | What it should be | How to (re)create it |
|---|---|---|
| `presentation_photo.jpg` | A printed or on-screen photo of a face, re-photographed by the webcam | Print (or display on a second screen) a photo of a team member's face, then photograph *that* with the demo webcam. |
| `presentation_screen_replay.mp4` | A face video played back on a phone/monitor and recaptured | Play a short (5-10s) selfie video on a phone screen, record the phone screen with the demo webcam. |
| `morphed_face.jpg` | A blended image of two identities | Use the `face_morpher` PyPI package (`pip install face_morpher`) on two team members' consenting, self-provided photos. Include a one-line consent/ethics note in the report per spec Section 6.2's fallback guidance. |
| `deepfake_sample.mp4` | A synthetically generated/altered face video | Use any public-domain/sample deepfake clip you have rights to use for a demo (e.g. one of the small samples researchers commonly link from the FaceForensics++ project page) - do **not** bulk-download the FaceForensics++ dataset itself here. |
| `replay_sample.jpg` | An exact copy of a previously-ACCEPTed genuine capture from this same demo session | After a successful "Live Capture" run, save the frame that was captured (e.g. add a "save last frame" step, or just re-run the live tab and screenshot) and drop it here. The point of this sample is that it's cryptographically/visually identical to prior genuine evidence - the replay detector (`detection/replay_detector.py`) should flag it via pHash match, not any of the content classifiers. |
| `injection_sample.mp4` | A screen-recorded or virtual-camera-sourced clip | Record your screen (e.g. Windows Game Bar / OBS) while playing back any face video, or route a video file through a virtual camera tool (e.g. OBS Virtual Camera) and record a few seconds through it. |

## Notes

- Keep files small (a few seconds of video, or a single JPEG) - these are
  for a live demo, not a benchmark.
- `client_demo/frame_utils.py` samples up to 8 frames from any `.mp4`/`.mov`
  file and a single frame from any `.jpg`/`.jpeg`/`.png`.
- The demo's "Simulate Attack" flow still runs the *real* session/nonce/
  challenge/signature flow (a fresh session is started per attempt) - only
  the biometric evidence itself is the pre-made attack file. This is
  intentional: it demonstrates that PQC channel security and a valid
  transaction binding alone don't stop a fraudulent biometric submission -
  only the AI detection pipeline (or, for `replay_sample.jpg`, the
  freshness/pHash mechanism) does.
