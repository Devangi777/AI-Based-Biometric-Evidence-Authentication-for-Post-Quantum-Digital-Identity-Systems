"""Generate the "Simulate Attack" demo samples from one genuine face photo.

    python scripts/make_demo_assets.py --face path/to/your_photo.jpg
    python scripts/make_demo_assets.py            # NASA public-domain portrait (needs scikit-image)

Writes demo_assets/attacks/ (gitignored). Each attack sample carries the
artifact that the corresponding real-world attack leaves, so the demo shows
the *intended* detector catching it. These are demo-scale stand-ins, not a
research dataset - see demo_assets/README-assets.md.

| File                            | Simulates                       | Artifact applied                                    |
|---------------------------------|---------------------------------|-----------------------------------------------------|
| genuine_sample.jpg              | bona fide still from a camera   | mild sensor noise, JPEG q=92                        |
| replay_sample.jpg               | resubmitted genuine capture     | byte-identical copy of genuine_sample.jpg           |
| presentation_photo.jpg          | printed photo held to camera    | lost detail, blur, low contrast, desaturated paper  |
| presentation_screen_replay.mp4  | face video replayed on a screen | moire grid, display blur, gamma shift               |
| morphed_face.jpg                | blend of two identities         | 50/50 blend, second face ~2.5% misaligned (ghosting) |
| deepfake_sample.mp4             | GAN-generated face video        | synthesised at 256 px, HF residual, upscaled        |
| injection_sample.mp4            | virtual-camera / file stream    | heavy re-encode; exact container frame timing       |

Videos include a small horizontal head movement so they satisfy a "turn your
head" liveness challenge and reach the AI detectors.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "demo_assets" / "attacks"
SIZE = 720  # square frame, roughly a webcam selfie crop
N_FRAMES, FPS = 30, 30  # 1 s clips: long enough for the injection timing check
rng = np.random.default_rng(2026)


def load_face(path: str | None) -> Image.Image:
    if path:
        img = Image.open(path).convert("RGB")
    else:
        try:
            from skimage import data
        except ImportError as exc:
            raise SystemExit("No --face given and scikit-image is not installed. "
                             "Pass --face <photo of a consenting person>, or `pip install scikit-image`.") from exc
        img = Image.fromarray(data.astronaut())  # NASA portrait of Eileen Collins, public domain
    side = min(img.size)
    left, top = (img.width - side) // 2, (img.height - side) // 2
    return img.crop((left, top, left + side, top + side)).resize((SIZE, SIZE), Image.LANCZOS)


def reframe(img: Image.Image, zoom: float, dx: float, dy: float) -> Image.Image:
    """A different shot of the same person: zoomed in by `zoom` and offset by
    (dx, dy) as fractions of the frame. Attack material comes from other
    photos/videos of the victim, not from the exact genuine capture, so each
    sample is reframed (otherwise the replay detector, correctly, flags them
    all as near-copies of genuine_sample.jpg)."""
    crop = SIZE / zoom
    left = (SIZE - crop) / 2 + dx * SIZE
    top = (SIZE - crop) / 2 + dy * SIZE
    return img.crop((left, top, left + crop, top + crop)).resize((SIZE, SIZE), Image.LANCZOS)


def camera(img: Image.Image, noise: float = 2.0) -> np.ndarray:
    arr = np.asarray(img, dtype=np.float64) + rng.normal(0, noise, (SIZE, SIZE, 3))
    return arr.clip(0, 255).astype(np.uint8)


def save_jpeg(arr: np.ndarray, name: str, quality: int = 92) -> Path:
    path = OUT / name
    Image.fromarray(arr).save(path, "JPEG", quality=quality)
    return path


def head_motion(img: Image.Image) -> list[Image.Image]:
    """Frames of the face sliding ~12% of the frame width, as a head turn would."""
    pad = SIZE // 8
    canvas = np.pad(np.asarray(img), ((0, 0), (pad, pad), (0, 0)), mode="edge")
    offsets = np.linspace(pad, 0, N_FRAMES).astype(int)
    return [Image.fromarray(canvas[:, o:o + SIZE]) for o in offsets]


def save_video(frames: list[np.ndarray], name: str) -> Path:
    import cv2

    path = OUT / name
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), FPS, (SIZE, SIZE))
    for f in frames:
        writer.write(cv2.cvtColor(f, cv2.COLOR_RGB2BGR))
    writer.release()
    return path


def printed_photo(img: Image.Image) -> np.ndarray:
    small = img.resize((SIZE // 4, SIZE // 4), Image.BILINEAR).resize((SIZE, SIZE), Image.BILINEAR)
    small = small.filter(ImageFilter.GaussianBlur(1.5))
    small = ImageEnhance.Contrast(small).enhance(0.55)
    small = ImageEnhance.Color(small).enhance(0.5)
    arr = np.asarray(small, dtype=np.float64) * np.array([1.0, 0.97, 0.88]) + 12  # warm paper tint
    return (arr + rng.normal(0, 1.5, arr.shape)).clip(0, 255).astype(np.uint8)


def screen_frame(img: Image.Image) -> np.ndarray:
    blurred = img.filter(ImageFilter.GaussianBlur(2.0))
    arr = np.asarray(blurred, dtype=np.float64) / 255.0
    arr = arr ** 0.8  # backlit display gamma
    yy, xx = np.indices((SIZE, SIZE))
    moire = 0.06 * np.sin(2 * np.pi * (xx * 0.11 + yy * 0.023))[..., None]  # pixel grid vs. sensor grid
    arr = 0.25 + 0.6 * arr + moire  # reduced dynamic range of a recaptured screen
    return (arr * 255).clip(0, 255).astype(np.uint8)


def morph(img: Image.Image, second: Image.Image | None) -> np.ndarray:
    """50/50 pixel blend of two identities whose landmarks are aligned only
    approximately (a ~2.5% offset), which leaves a ghosted double contour.
    Without a second photo, the first face stands in for both identities."""
    a = np.asarray(img, dtype=np.float64)
    b = np.asarray(second, dtype=np.float64) if second is not None else a
    b = np.roll(b, (SIZE // 120, SIZE // 40), axis=(0, 1))
    return camera(Image.fromarray((0.5 * a + 0.5 * b).astype(np.uint8)), noise=1.5)


def gan_frame(img: Image.Image) -> np.ndarray:
    """Face-swap generators synthesise at low resolution (here 256 px) and
    the result is upscaled into the frame; the generator's upsampling layers
    leave excess broadband high-frequency energy (Frank et al., ICML 2020)."""
    low = np.asarray(img.resize((256, 256), Image.BILINEAR), dtype=np.float64)
    low += rng.normal(0, 40, (256, 256))[..., None]
    return np.asarray(Image.fromarray(low.clip(0, 255).astype(np.uint8)).resize((SIZE, SIZE), Image.NEAREST))


def reencoded(img: Image.Image) -> np.ndarray:
    from io import BytesIO

    buf = BytesIO()
    img.save(buf, "JPEG", quality=20)
    return np.asarray(Image.open(buf).convert("RGB"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--face", help="photo of a consenting person (frontal, well lit)")
    parser.add_argument("--second-face", help="optional second consenting person for the morph sample")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    face = load_face(args.face)
    second = load_face(args.second_face) if args.second_face else None

    written = [
        save_jpeg(camera(face), "genuine_sample.jpg"),
        save_jpeg(printed_photo(reframe(face, 1.25, 0.04, 0.03)), "presentation_photo.jpg"),
        save_jpeg(morph(reframe(face, 1.2, -0.04, 0.02), second), "morphed_face.jpg"),
        save_video([screen_frame(f) for f in head_motion(reframe(face, 1.45, -0.06, 0.06))], "presentation_screen_replay.mp4"),
        save_video([gan_frame(f) for f in head_motion(reframe(face, 1.25, -0.03, -0.02))], "deepfake_sample.mp4"),
        save_video([reencoded(f) for f in head_motion(reframe(face, 1.1, 0.0, 0.08))], "injection_sample.mp4"),
    ]
    shutil.copyfile(OUT / "genuine_sample.jpg", OUT / "replay_sample.jpg")
    written.append(OUT / "replay_sample.jpg")

    for path in written:
        print(f"wrote {path.relative_to(REPO)} ({path.stat().st_size // 1024} kB)")


if __name__ == "__main__":
    main()
