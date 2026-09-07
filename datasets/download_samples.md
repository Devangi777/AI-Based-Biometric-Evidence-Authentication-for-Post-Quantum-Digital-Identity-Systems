# Full-scale evaluation datasets (not downloaded here)

Per the build instructions, no full research datasets were downloaded into
this environment - `evaluation/benchmark.py` runs against small synthetic
samples and (optionally) the `demo_assets/attacks/` files instead, which is
enough to prove the pipeline works end-to-end but is **explicitly not** a
real accuracy result (see the loud warning `evaluation/benchmark.py` prints,
and `detection/README-models.md`).

This file documents what each real dataset would add, and how to get it, so
a full-scale evaluation is a scoped follow-up rather than a mystery.

## FaceForensics++ (c23 compressed subset)

- **Adds:** labeled real/fake video pairs for `detection/deepfake_detector.py`
  - both a pretrained Meso4 checkpoint (or fine-tuning target) and a proper
    held-out test split for real accuracy/APCER/BPCER numbers.
- **Access:** request form at https://github.com/ondyari/FaceForensics -
  approval is not instant; spec Section 10 flags this as a Week-1 Day-1 risk
  for exactly this reason.
- **Scale:** the c23 (compressed) subset is still tens of GB; for this
  project's evaluation, a small stratified sample (e.g. 50-100 clips per
  manipulation method) is enough for a meaningful test split without
  needing the full corpus.

## CelebA-Spoof

- **Adds:** labeled live/spoof face images for
  `detection/presentation_attack.py` - real accuracy numbers, and a source
  of negative (attack) examples beyond what `demo_assets/attacks/` bundles.
- **Access:** https://github.com/ZhangYuanhan-AI/CelebA-Spoof - public,
  no approval form, but large (~600K images); a random stratified subset
  (a few thousand images balanced across spoof types) is sufficient here.
- **Alternative:** CASIA-FASD (smaller, also public) if CelebA-Spoof's size
  is impractical for the team's storage/Colab quota.

## AMSL Face Morph Image Dataset

- **Adds:** real morphed-face samples for `detection/morph_detector.py`
  threshold tuning and accuracy evaluation, beyond the single self-generated
  `morphed_face.jpg` demo sample.
- **Access:** https://omen.cs.uni-magdeburg.de/disclaimer/index.php -
  **requires an approval-form request**, flagged in spec Section 10 as a
  Week-1 risk. Request this immediately if the team wants real morph-
  detection numbers; the `face_morpher`-generated fallback (see
  `demo_assets/README-assets.md`) is a reasonable stand-in for the demo but
  not for a real accuracy claim, since self-generated morphs on 1-2 photo
  pairs are not representative of morph-attack diversity.

## What NOT to do

Do not bulk-download any of the above into `datasets/` automatically or as
part of a coding-agent task - they require explicit access requests
(FaceForensics++, AMSL) and/or are large enough (CelebA-Spoof) that
downloading them should be a deliberate, team-approved action with adequate
disk space, not a side effect of running a build script.
