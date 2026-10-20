# Demo attack samples

Samples for the dashboard's **Simulate Attack** and **Tamper with Protocol**
tabs and for `scripts/demo_check.py`. They are demo-scale stand-ins built
from one face photo, not a research dataset; see `datasets/download_samples.md`
for the datasets real accuracy figures would need.

The files are gitignored. Generate them on each machine:

```bash
python scripts/make_demo_assets.py                         # NASA public-domain portrait (needs scikit-image)
python scripts/make_demo_assets.py --face me.jpg           # a consenting person's frontal photo
python scripts/make_demo_assets.py --face a.jpg --second-face b.jpg   # real two-identity morph
```

| File | Simulates | Artifact | Expected decision |
|---|---|---|---|
| `genuine_sample.jpg` | Bona fide still from a camera | Mild sensor noise, JPEG q=92 | ACCEPT |
| `replay_sample.jpg` | Resubmission of an accepted capture | Byte-identical copy of the genuine sample | REJECT: replay |
| `presentation_photo.jpg` | Printed photo held to the camera | Lost detail, blur, low contrast, paper tint | REJECT: presentation attack |
| `presentation_screen_replay.mp4` | Face video replayed on a screen | Display blur and gamma, moiré grid | REJECT: presentation attack (+ morph, injection) |
| `morphed_face.jpg` | Blend of two identities | 50/50 blend, second face ~2.5% misaligned | REJECT: morph |
| `deepfake_sample.mp4` | GAN-generated face video | Synthesised at 256 px with HF residual, upscaled | REJECT: deepfake (+ injection) |
| `injection_sample.mp4` | Virtual camera / file stream | Heavy re-encode; exact container frame timing | REJECT: injection |

Each attack sample is a differently framed shot of the face, as real attack
material would come from other photos of the victim. Otherwise the replay
detector would (correctly) flag them all as near-copies of the genuine
sample. Videos are 1 s at 30 fps (long enough for the injection timing
check) and include a small head movement so they satisfy a head-turn
liveness challenge and reach the detectors.

The replay sample is only rejected after the genuine sample has been
submitted on the same server run. That's the point: it's an exact copy of
evidence the server has already seen. Use the dashboard's **Reset replay
memory** (with `DEMO_MODE=true`) to rehearse again.

The dashboard's upload box also accepts any `.jpg`/`.png`/`.mp4`/`.mov`, for
example a phone photo of a printed picture, or a screen recording.
