# Detection models: pretrained checkpoints vs. mock mode

Per the build instructions, no research datasets or model checkpoints were
downloaded in this environment. Every module in `detection/` works today in
**mock mode** (deterministic, dependency-light heuristics - see each
module's docstring for exactly what it computes and why it's a legitimate,
if weaker, proxy). This file documents what to add to switch each module to
its real pretrained model, per spec Section 6.

## 1. Presentation Attack Detection - `detection/presentation_attack.py`

- **Model:** MiniFASNet, from the [Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing) repo (minivision-ai).
- **What to add:**
  1. Vendor `src/model_lib/MiniFASNet.py` (architecture) from that repo into
     `detection/architectures/minifasnet.py`.
  2. Download a released checkpoint from that repo's
     `resources/anti_spoof_models/` directory (e.g.
     `2.7_80x80_MiniFASNetV2.pth`) to `detection/weights/pad_minifasnet.pth`.
  3. Update `PresentationAttackDetector._try_load_model` to import the
     vendored architecture, `load_state_dict`, and `.eval()` it, then
     implement `_predict_pretrained` to match that repo's documented
     preprocessing (80x80 or 128x128 crop depending on checkpoint variant,
     BGR channel order, specific normalization).
- **Dataset for evaluation:** CelebA-Spoof (subset) or CASIA-FASD.

## 2. Face Morphing Detection - `detection/morph_detector.py`

Already has a real (non-mock) implementation when MediaPipe Face Mesh is
installed - no external checkpoint needed, per spec Section 6.2's own
guidance that a non-ML feature-based approach is acceptable. To improve it
further:

- **Dataset for evaluation/threshold tuning:** [AMSL Face Morph Image Dataset](https://omen.cs.uni-magdeburg.de/disclaimer/index.php)
  (public, but requires an approval-form request - flagged in spec Section
  10 as a Week-1 risk).
- **Fallback if access is delayed:** generate a small synthetic morph set
  with the `face_morpher` PyPI package on two team members' own photos
  (with a consent/ethics note in the report) - this is exactly what
  `demo_assets/README-assets.md` describes for `morphed_face.jpg`.

## 3. Deepfake Detection - `detection/deepfake_detector.py`

- **Model:** Meso4 (Afchar et al. 2018) - the architecture is already
  correctly defined in this file (`_build_meso4`); only a trained checkpoint
  is missing.
- **What to add:** a Meso4 checkpoint trained on FaceForensics++ (c23
  compressed subset). Community-shared checkpoints exist (search
  "MesoNet pretrained weights FaceForensics++"); place the `.pth` file
  (a `state_dict`, input 256x256 RGB, output 2 logits: `[real, fake]`) at
  `detection/weights/deepfake_meso4.pth`.
- **Heavier alternative per spec:** Xception or EfficientNet-B4 fine-tuned
  on FaceForensics++ - more citable/benchmarked, but needs a different
  architecture file and more Colab GPU time to fine-tune if no pretrained
  checkpoint is found; only worth it if Meso4's accuracy is insufficient.
- **Dataset:** FaceForensics++ c23 subset, via the documented request
  process at https://github.com/ondyari/FaceForensics.

## 4. Replay Attack Detection - `detection/replay_detector.py`

No model needed - implemented in full per spec Section 6.4 (pHash-based
freshness store, `imagehash.phash` + Hamming-distance matching within
`REPLAY_HASH_WINDOW_SECONDS`). Nothing to add here.

## 5. Injection Attack Detection - `detection/injection_detector.py`

Per spec Section 10, "limited public datasets exist here" and the module is
expected to stay heuristic + ML hybrid rather than a fully solved
classifier. Currently: real frame-timing heuristic (needs no model) +
compression-block-boundary heuristic. To add the CNN half:

- **What to add:** train a small CNN (binary: real-camera vs.
  virtual-camera/re-encoded) on your own collected samples - there is no
  standard public benchmark checkpoint to point at for this task, which is
  itself part of the documented limitation (spec Section 10). Save as
  `detection/weights/injection_cnn.pth` and wire it into
  `InjectionDetector._try_load_model` the same way `deepfake_detector.py`
  does for Meso4.

## General notes

- All checkpoint paths are gitignored (`*.pth` etc. in `.gitignore`) - never
  commit model weights.
- `DETECTION_MODE=mock` (see `.env.example`) forces every module into its
  mock/heuristic path regardless of whether checkpoints are present - useful
  for CI or fast offline iteration once real models are added.
- Every mock-mode score is a real, documented signal-processing heuristic
  (Laplacian sharpness, FFT high-frequency ratio, block-boundary energy,
  landmark/pixel symmetry) calibrated by eye against a handful of webcam
  frames, **not** fit to any labeled dataset. Treat mock-mode accuracy
  numbers from `evaluation/benchmark.py` as a pipeline smoke test, not a
  meaningful detection-accuracy result - the real numbers come once
  pretrained checkpoints are wired in per the sections above.
