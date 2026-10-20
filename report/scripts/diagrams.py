"""Architecture and protocol diagrams for the final report (matplotlib only,
so no Graphviz/Mermaid toolchain is needed)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

FIG = Path(__file__).resolve().parents[1] / "figures"
FIG.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.size": 9})

BLUE, BLUE_L = "#2a6fbb", "#e3eefa"
ORANGE, ORANGE_L = "#c46f12", "#fdf0e1"
GREEN, GREEN_L = "#23864a", "#e4f4ea"
RED, RED_L = "#b3261e", "#fbe7e5"
GREY, GREY_L = "#5f6b7a", "#f2f4f7"


def box(ax, x, y, w, h, text, edge, face, fs=8.5, bold=False, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                lw=1.2, ec=edge, fc=face, ls=ls))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", wrap=True)


def arrow(ax, x1, y1, x2, y2, color="black", ls="-", lw=1.2, text=None, fs=7.5, rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=10,
                                 color=color, lw=lw, ls=ls, connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.12, text, ha="center", va="bottom", fontsize=fs, color=color)


def architecture() -> None:
    fig, ax = plt.subplots(figsize=(12, 8.2))
    ax.set_xlim(0, 24)
    ax.set_ylim(0, 16.4)
    ax.axis("off")

    # --- Quantum adversary layer -------------------------------------------
    ax.add_patch(FancyBboxPatch((0.3, 12.6), 23.4, 3.5, boxstyle="round,pad=0.02,rounding_size=0.2",
                                lw=1.4, ec=RED, fc="#fff8f7", ls="--"))
    ax.text(0.6, 15.75, "QUANTUM ADVERSARY MODEL (circuits simulated in Qiskit, Section 3.2)", fontsize=9.5, fontweight="bold", color=RED)
    box(ax, 0.8, 13.0, 5.4, 2.3, "Shor's algorithm\nQFT order finding\n⇒ breaks RSA-3072, ECDSA-P256,\nX25519 in poly-time",
        RED, RED_L)
    box(ax, 6.7, 13.0, 5.4, 2.3, "Grover's algorithm\namplitude amplification\n⇒ AES-256 → 128-bit,\nSHA-256 preimage → 128-bit", RED, RED_L)
    box(ax, 12.6, 13.0, 5.4, 2.3, "Harvest-now, decrypt-later\nrecord biometric sessions\ntoday, decrypt with a future\nCRQC", RED, RED_L)
    box(ax, 18.5, 13.0, 4.8, 2.3, "Quantum entropy (QRNG)\nH⊗n |0⟩ → uniform bits\n⇒ session nonce source\n(defensive use)", GREEN, GREEN_L)

    # --- Client ---------------------------------------------------------------
    ax.add_patch(FancyBboxPatch((0.3, 0.4), 7.4, 11.7, boxstyle="round,pad=0.02,rounding_size=0.2",
                                lw=1.2, ec=BLUE, fc="#fbfdff"))
    ax.text(4.0, 11.65, "CLIENT (Streamlit, webcam)", ha="center", fontsize=9.5, fontweight="bold", color=BLUE)
    cy = [9.9, 8.0, 6.1, 4.2, 2.3]
    labels = [
        "1. Receive session: nonce N (32 B),\nchallenge C, ML-KEM pk",
        "2. Capture frames while\nperforming challenge C",
        "3. h = SHA-256(frames)\n(Grover-resistant: 128-bit PQ)",
        "4. σ = ML-DSA-65.Sign(\nh ‖ N ‖ ts ‖ resp)",
        "5. (ct, K) = ML-KEM-768.Encaps(pk)\nk = HKDF(K, salt=N); seal payload\nwith AES-256-GCM (AAD = session id)",
    ]
    for y, t in zip(cy, labels):
        box(ax, 0.8, y, 6.4, 1.45, t, BLUE, BLUE_L, fs=8)
    for a, b in zip(cy[:-1], cy[1:]):
        arrow(ax, 4.0, a, 4.0, b + 1.45, BLUE)

    # --- Channel --------------------------------------------------------------
    box(ax, 8.4, 5.2, 3.6, 3.0, "Quantum-safe\nchannel\n\nML-KEM-768 (FIPS 203)\nMLWE hardness\nIND-CCA2", GREY, GREY_L, fs=8, bold=False)
    arrow(ax, 7.2, 3.0, 10.2, 5.2, BLUE, text="ct, Enc_k(payload)", rad=0.15)
    arrow(ax, 12.0, 7.4, 13.2, 10.2, GREY, rad=0.25)

    # --- Server ---------------------------------------------------------------
    ax.add_patch(FancyBboxPatch((12.7, 0.4), 11.0, 11.7, boxstyle="round,pad=0.02,rounding_size=0.2",
                                lw=1.2, ec=ORANGE, fc="#fffcf8"))
    ax.text(18.2, 11.65, "SERVER (FastAPI + liboqs + PyTorch/MediaPipe)", ha="center", fontsize=9.5, fontweight="bold", color=ORANGE)
    box(ax, 13.2, 9.9, 4.9, 1.45, "6. K = ML-KEM.Decaps(sk, ct)\nk = HKDF(K); AES-GCM open (tag)", ORANGE, ORANGE_L, fs=8)
    box(ax, 13.2, 6.4, 4.9, 3.0,
        "7. Transaction-binding gate\n(a) ML-DSA.Verify(σ) over stored N\n(b) nonce N unused\n(c) |now − ts| ≤ 30 s\n(d) challenge C fulfilled\n(e) SHA-256(frames) = h",
        ORANGE, ORANGE_L, fs=8, bold=False)
    arrow(ax, 15.65, 9.9, 15.65, 9.4, ORANGE)
    box(ax, 13.2, 4.3, 4.9, 1.5, "REJECT early\n(no AI cost, < 1 ms)", RED, RED_L, fs=8)
    arrow(ax, 15.65, 6.4, 15.65, 5.8, RED, text="any check fails", fs=7)

    box(ax, 18.6, 3.0, 4.7, 6.4, "", ORANGE, ORANGE_L)
    ax.text(20.95, 9.0, "8. AI attack-detection\npipeline", ha="center", va="top", fontsize=8.5, fontweight="bold")
    dets = ["PAD (sharpness, gamut)", "Morph (ghosting, mirror\nsymmetry of fine detail)", "Deepfake (FFT HF ratio /\nMeso4)",
            "Replay (pHash, Hamming ≤ 8)", "Injection (timing jitter,\n8×8 block energy)"]
    for i, d in enumerate(dets):
        box(ax, 18.9, 7.25 - i * 0.92, 4.1, 0.78, d, GREY, "white", fs=7.2)
    arrow(ax, 18.1, 7.9, 18.6, 7.9, GREEN, text="all pass", fs=7)

    box(ax, 18.6, 0.8, 4.7, 1.7, "9. Fusion: S = Σ wᵢsᵢ\nACCEPT iff S ≥ 0.6\nand ∀i: sᵢ ≥ τᵢ (veto)", GREEN, GREEN_L, fs=8)
    arrow(ax, 20.95, 3.0, 20.95, 2.5, GREEN)
    box(ax, 13.2, 0.8, 4.9, 1.7, "10. Decision + per-stage\nlatency → client\n(nonce marked used)", GREY, GREY_L, fs=8)
    arrow(ax, 18.6, 1.65, 18.1, 1.65, GREY)

    # Threat-to-countermeasure links
    arrow(ax, 3.5, 13.0, 10.2, 8.25, RED, ls=":", lw=1.0, rad=-0.15)
    WB = dict(boxstyle="round,pad=0.2", fc="white", ec="none")
    ax.text(10.2, 10.2, "Shor + HNDL\nneutralised by\nML-KEM / ML-DSA", fontsize=7, color=RED, ha="center", bbox=WB)
    arrow(ax, 9.4, 13.0, 4.0, 7.45, RED, ls=":", lw=1.0, rad=0.1)
    ax.text(9.6, 12.15, "Grover absorbed by 256-bit\nsymmetric / hash sizes", fontsize=7, color=RED, ha="center", bbox=WB)
    arrow(ax, 15.3, 13.0, 10.2, 8.25, RED, ls=":", lw=1.0, rad=0.15)
    arrow(ax, 20.9, 13.0, 4.0, 11.35, GREEN, ls=":", lw=1.0, rad=0.12)
    ax.text(16.6, 12.2, "QRNG → nonce N", fontsize=7, color=GREEN, bbox=WB)

    fig.tight_layout()
    fig.savefig(FIG / "fig_a1_architecture.png", dpi=300)
    plt.close(fig)


def sequence() -> None:
    fig, ax = plt.subplots(figsize=(11, 7.6))
    ax.set_xlim(0, 22)
    ax.set_ylim(0, 16)
    ax.axis("off")
    lanes = {"Client": 2.5, "Server API": 9.0, "Session store": 14.0, "Detectors + fusion": 19.2}
    for name, x in lanes.items():
        box(ax, x - 1.8, 14.8, 3.6, 0.9, name, GREY, GREY_L, fs=9, bold=True)
        ax.plot([x, x], [0.4, 14.8], color=GREY, lw=0.8, ls="--")

    C, S, ST, D = lanes.values()
    steps = [
        (C, S, "POST /session/start"),
        (S, ST, "UUID, N←{0,1}²⁵⁶, C←challenges, (pk,sk)←ML-KEM.KeyGen, ML-DSA keys"),
        (S, C, "session_id, N, C, pk_KEM, pk_DSA, window=30 s"),
        (C, C, "capture frames, h = SHA-256(frames), ts = now()"),
        (C, S, "POST /evidence (h, ts, resp) → σ = ML-DSA.Sign(h‖N‖ts‖resp)"),
        (C, C, "(ct, K) ← Encaps(pk); c = AES-GCM[HKDF(K, N)](payload)"),
        (C, S, "POST /verify-sealed (ct, GCM nonce, c)"),
        (S, S, "K = Decaps(sk, ct); open c (bad tag ⇒ REJECT)"),
        (S, ST, "Verify(σ) over stored N; N unused?; |Δt| ≤ 30 s; C met?; SHA-256(frames) = h?"),
        (ST, S, "mark N used (consumed even on failure)"),
        (S, D, "only if every check passes: PAD, Morph, Deepfake, Replay, Injection"),
        (D, S, "scores s₁..s₅ → fused S, veto list"),
        (S, C, "ACCEPT / REJECT, reasons, timing_ms"),
    ]
    y = 14.1
    for a, b, t in steps:
        y -= 0.95
        if a == b:
            ax.add_patch(FancyBboxPatch((a - 1.6, y - 0.3), 7.0, 0.6, boxstyle="round,pad=0.02",
                                        fc=BLUE_L, ec=BLUE, lw=0.8))
            ax.text(a + 1.9, y, t, ha="center", va="center", fontsize=7.5)
            continue
        color = BLUE if a == C else ORANGE if a == S else GREEN
        arrow(ax, a, y, b, y, color)
        ax.text((a + b) / 2, y + 0.1, t, ha="center", va="bottom", fontsize=7.5,
                bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none"))
    fig.tight_layout()
    fig.savefig(FIG / "fig_a2_binding_sequence.png", dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    sequence()
