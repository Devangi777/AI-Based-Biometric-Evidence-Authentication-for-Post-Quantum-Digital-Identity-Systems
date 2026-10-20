"""System-level experiments for the final report (Section 4.4).

Everything runs against the real project code - liboqs ML-KEM/ML-DSA, the
transaction binding, the five detectors and the fusion engine - and the
pipeline experiments drive the actual demo client (client_demo/api_client.py)
with its HTTP calls routed in-process to the FastAPI app:

  S1. PQC vs. classical primitives across NIST levels (latency + sizes), and
      the AES-256-GCM cost of sealing a verification payload.
  S2. Scenario matrix: the same 12 scenarios as scripts/demo_check.py (face-
      derived samples from scripts/make_demo_assets.py + protocol tampering),
      plus two synthetic controls - which layer stops which attack.
  S3. 40 distinct genuine sessions over the sealed channel: latency
      breakdown and false-reject count.

Run from the repo root with the project venv:
  python scripts/make_demo_assets.py      # if demo_assets/attacks/ is empty
  python report/scripts/system_experiments.py
"""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import statistics
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]  # report/
REPO = ROOT.parent
sys.path.insert(0, str(REPO))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

FIG = ROOT / "figures"
DATA = ROOT / "data"
FIG.mkdir(parents=True, exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.size": 10})

N_CRYPTO = 500
N_E2E = 40


def write_csv(rows: list[dict], name: str) -> None:
    with open(DATA / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def time_ms(fn, n: int) -> tuple[float, float]:
    fn()  # warm-up
    xs = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1000)
    return statistics.median(xs), statistics.mean(xs)


# ---------------------------------------------------------------------------
# S1. Primitive benchmark
# ---------------------------------------------------------------------------
def bench_primitives() -> list[dict]:
    import oqs
    from cryptography.hazmat.primitives.asymmetric import x25519

    from crypto import classical_baseline as cb

    rows = []
    for alg, level in (("ML-KEM-512", 1), ("ML-KEM-768", 3), ("ML-KEM-1024", 5)):
        kem = oqs.KeyEncapsulation(alg)
        pk = kem.generate_keypair()
        ct, _ = oqs.KeyEncapsulation(alg).encap_secret(pk)
        kg = time_ms(lambda: oqs.KeyEncapsulation(alg).generate_keypair(), N_CRYPTO)
        en = time_ms(lambda: oqs.KeyEncapsulation(alg).encap_secret(pk), N_CRYPTO)
        de = time_ms(lambda: kem.decap_secret(ct), N_CRYPTO)
        d = kem.details
        rows.append({"scheme": alg, "family": "KEM (PQC, lattice)", "nist_level": level, "quantum_safe": "Yes",
                     "keygen_ms": kg[0], "op1_ms": en[0], "op2_ms": de[0], "op1": "encaps", "op2": "decaps",
                     "public_key_B": d["length_public_key"], "secret_key_B": d["length_secret_key"],
                     "ct_or_sig_B": d["length_ciphertext"]})

    rsa_priv, rsa_pub = cb.rsa_generate_keypair()
    payload = b"\x00" * 32
    rct = cb.rsa_encrypt(rsa_pub, payload)
    rows.append({"scheme": "RSA-3072 (OAEP)", "family": "KEM analogue (classical)", "nist_level": "~1 (128-bit)",
                 "quantum_safe": "No (Shor)",
                 "keygen_ms": time_ms(cb.rsa_generate_keypair, 30)[0],
                 "op1_ms": time_ms(lambda: cb.rsa_encrypt(rsa_pub, payload), N_CRYPTO)[0],
                 "op2_ms": time_ms(lambda: cb.rsa_decrypt(rsa_priv, rct), N_CRYPTO)[0],
                 "op1": "encrypt", "op2": "decrypt",
                 "public_key_B": cb.public_key_size_bytes(rsa_pub), "secret_key_B": "", "ct_or_sig_B": len(rct)})

    a = x25519.X25519PrivateKey.generate()
    b_pub = x25519.X25519PrivateKey.generate().public_key()
    rows.append({"scheme": "X25519 (ECDH)", "family": "KEM analogue (classical)", "nist_level": "~1 (128-bit)",
                 "quantum_safe": "No (Shor)",
                 "keygen_ms": time_ms(x25519.X25519PrivateKey.generate, N_CRYPTO)[0],
                 "op1_ms": time_ms(lambda: a.exchange(b_pub), N_CRYPTO)[0], "op2_ms": "",
                 "op1": "exchange", "op2": "",
                 "public_key_B": 32, "secret_key_B": 32, "ct_or_sig_B": 32})

    msg = hashlib.sha256(b"x").digest() + b"\x01" * 32 + b"2026-10-18T00:00:00+00:00" + b"Turn your head slightly left"
    for alg, level in (("ML-DSA-44", 2), ("ML-DSA-65", 3), ("ML-DSA-87", 5)):
        s = oqs.Signature(alg)
        pk = s.generate_keypair()
        sig = s.sign(msg)
        v = oqs.Signature(alg)
        d = s.details
        rows.append({"scheme": alg, "family": "Signature (PQC, lattice)", "nist_level": level, "quantum_safe": "Yes",
                     "keygen_ms": time_ms(lambda: oqs.Signature(alg).generate_keypair(), N_CRYPTO)[0],
                     "op1_ms": time_ms(lambda: s.sign(msg), N_CRYPTO)[0],
                     "op2_ms": time_ms(lambda: v.verify(msg, sig, pk), N_CRYPTO)[0],
                     "op1": "sign", "op2": "verify",
                     "public_key_B": d["length_public_key"], "secret_key_B": d["length_secret_key"],
                     "ct_or_sig_B": len(sig)})

    ec_priv, ec_pub = cb.ecdsa_generate_keypair()
    ec_sig = cb.ecdsa_sign(ec_priv, msg)
    rows.append({"scheme": "ECDSA-P256", "family": "Signature (classical)", "nist_level": "~1 (128-bit)",
                 "quantum_safe": "No (Shor)",
                 "keygen_ms": time_ms(cb.ecdsa_generate_keypair, N_CRYPTO)[0],
                 "op1_ms": time_ms(lambda: cb.ecdsa_sign(ec_priv, msg), N_CRYPTO)[0],
                 "op2_ms": time_ms(lambda: cb.ecdsa_verify(ec_pub, msg, ec_sig), N_CRYPTO)[0],
                 "op1": "sign", "op2": "verify",
                 "public_key_B": cb.public_key_size_bytes(ec_pub), "secret_key_B": "", "ct_or_sig_B": len(ec_sig)})
    write_csv(rows, "s1_primitives.csv")
    return rows


def plot_primitives(rows: list[dict]) -> None:
    by = {r["scheme"]: r for r in rows}
    # Latency of the operations actually on the verification critical path
    ops = [
        ("ML-KEM-768\nencaps+decaps", by["ML-KEM-768"]["op1_ms"] + by["ML-KEM-768"]["op2_ms"], "#2a6fbb"),
        ("RSA-3072\nenc+dec", by["RSA-3072 (OAEP)"]["op1_ms"] + by["RSA-3072 (OAEP)"]["op2_ms"], "#9aa5b1"),
        ("X25519\nexchange", by["X25519 (ECDH)"]["op1_ms"], "#9aa5b1"),
        ("ML-DSA-65\nsign+verify", by["ML-DSA-65"]["op1_ms"] + by["ML-DSA-65"]["op2_ms"], "#2a6fbb"),
        ("ECDSA-P256\nsign+verify", by["ECDSA-P256"]["op1_ms"] + by["ECDSA-P256"]["op2_ms"], "#9aa5b1"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    ax = axes[0]
    ax.bar([o[0] for o in ops], [o[1] for o in ops], color=[o[2] for o in ops])
    for i, o in enumerate(ops):
        ax.text(i, o[1], f"{o[1]:.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("(a) Per-verification crypto latency")
    ax.tick_params(axis="x", labelsize=8)
    ax.spines[["top", "right"]].set_visible(False)

    ax = axes[1]
    sizes = [
        ("ML-KEM-768", by["ML-KEM-768"]["public_key_B"], by["ML-KEM-768"]["ct_or_sig_B"]),
        ("RSA-3072", by["RSA-3072 (OAEP)"]["public_key_B"], by["RSA-3072 (OAEP)"]["ct_or_sig_B"]),
        ("X25519", 32, 32),
        ("ML-DSA-65", by["ML-DSA-65"]["public_key_B"], by["ML-DSA-65"]["ct_or_sig_B"]),
        ("ECDSA-P256", by["ECDSA-P256"]["public_key_B"], by["ECDSA-P256"]["ct_or_sig_B"]),
    ]
    x = np.arange(len(sizes))
    ax.bar(x - 0.2, [s[1] for s in sizes], 0.4, label="Public key", color="#2a6fbb")
    ax.bar(x + 0.2, [s[2] for s in sizes], 0.4, label="Ciphertext / signature", color="#e08a2c")
    ax.set_xticks(x, [s[0] for s in sizes], fontsize=8)
    ax.set_yscale("log")
    ax.set_ylabel("Bytes (log scale)")
    ax.set_title("(b) Wire-size cost")
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "fig_r1_pqc_vs_classical.png", dpi=300)
    plt.close(fig)

    pqc = [r for r in rows if r["scheme"].startswith("ML-")]
    fig, ax = plt.subplots(figsize=(7, 3.4))
    labels = [r["scheme"] for r in pqc]
    x = np.arange(len(labels))
    ax.bar(x - 0.27, [r["keygen_ms"] for r in pqc], 0.27, label="KeyGen", color="#5b8fd1")
    ax.bar(x, [r["op1_ms"] for r in pqc], 0.27, label="Encaps / Sign", color="#2a6fbb")
    ax.bar(x + 0.27, [r["op2_ms"] for r in pqc], 0.27, label="Decaps / Verify", color="#e08a2c")
    ax.set_xticks(x, labels, fontsize=8)
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("ML-KEM / ML-DSA latency across NIST security levels")
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "fig_r2_pqc_levels.png", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Synthetic frames - only for the repeated-run latency / false-reject run
# (S3), where 40 *distinct* captures are needed. The scenario matrix (S2)
# uses the face-derived samples from scripts/make_demo_assets.py.
# ---------------------------------------------------------------------------
def natural_frame(seed: int, size: int = 240) -> np.ndarray:
    """1/f^1.2 amplitude-spectrum luminance (natural-image statistics) with
    correlated colour channels, plus sigma=6 sensor noise."""
    rng = np.random.default_rng(seed)
    fy, fx = np.fft.fftfreq(size)[:, None], np.fft.fftfreq(size)[None, :]
    f = np.hypot(fy, fx)
    f[0, 0] = 1

    def texture(scale: float) -> np.ndarray:
        img = np.real(np.fft.ifft2((rng.normal(size=(size, size)) + 1j * rng.normal(size=(size, size))) / f**1.2))
        return (img - img.mean()) / img.std() * scale

    # Camera images have strongly correlated RGB channels: shared light and
    # shadow (luminance, including near-black) plus smaller colour variation.
    luminance = texture(60) + 120
    arr = np.stack([luminance + texture(18) for _ in range(3)], -1) + rng.normal(0, 6, (size, size, 3))
    return arr.clip(0, 255).astype(np.uint8)


def white_noise_frame(seed: int) -> np.ndarray:
    """What evaluation/benchmark.py used as 'genuine' before this fix."""
    return np.random.default_rng(seed).integers(0, 256, size=(240, 240, 3), dtype=np.uint8)


def live_timestamps(seed: int, n: int = 60) -> list[float]:
    rng = np.random.default_rng(seed)
    return list(np.cumsum(np.r_[time.time(), rng.normal(1 / 30, 0.0017, n - 1)]))


# ---------------------------------------------------------------------------
# The real demo client (client_demo/api_client.py), with its HTTP calls
# routed in-process to the FastAPI app instead of over the network.
# ---------------------------------------------------------------------------
def in_process_client():
    from fastapi.testclient import TestClient

    from client_demo import api_client
    from server.main import app

    client = TestClient(app)

    def _request(method: str, path: str, **kwargs) -> dict:
        resp = client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            raise api_client.ApiError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text}")
        return resp.json()

    api_client._request = _request
    return api_client


def demo_scenarios() -> list[tuple]:
    import importlib.util

    spec = importlib.util.spec_from_file_location("demo_check", REPO / "scripts" / "demo_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SCENARIOS


ATTACK_CLASS = {
    "genuine_sample.jpg": "Bona fide",
    "replay_sample.jpg": "Replay (content)",
    "presentation_photo.jpg": "Presentation attack",
    "presentation_screen_replay.mp4": "Presentation attack",
    "morphed_face.jpg": "Morphing",
    "deepfake_sample.mp4": "Deepfake",
    "injection_sample.mp4": "Injection",
}
TAMPER_CLASS = {
    "stale_timestamp": "Replay (temporal)",
    "swap_frames": "Evidence substitution",
    "reuse_nonce": "Replay (session)",
    "wrong_challenge": "Liveness (pre-recorded)",
    "corrupt_channel": "Channel tampering (MITM)",
}
MODULES = ["presentation_attack", "morph", "deepfake", "replay", "injection"]


def stopped_by(resp: dict) -> str:
    if resp["accepted"]:
        return "—"
    failed = [k for k, ok in resp["binding_checks"].items() if not ok]
    if failed:
        return "Binding: " + ", ".join(failed)
    return "AI: " + ", ".join(resp.get("below_threshold_modules") or ["fused score"])


# ---------------------------------------------------------------------------
# S2. Scenario matrix (identical to scripts/demo_check.py) + controls
# ---------------------------------------------------------------------------
def scenario_matrix(api) -> list[dict]:
    from client_demo.frame_utils import load_attack_file
    from detection.replay_detector import store as replay_store

    attacks_dir = REPO / "demo_assets" / "attacks"
    if not (attacks_dir / "genuine_sample.jpg").exists():
        raise SystemExit("demo_assets/attacks/ is empty - run scripts/make_demo_assets.py first")

    replay_store.clear()
    rows = []
    for label, filename, tamper, expected, _ in demo_scenarios():
        frames, frame_ts = load_attack_file(attacks_dir / filename)
        _, resp = api.run_verification(frames, frame_ts, tamper=tamper, sealed=True)
        rows.append(_scenario_row(label, TAMPER_CLASS.get(tamper) or ATTACK_CLASS[filename], expected, resp))

    controls = [
        ("Control: natural-statistics texture, no face", [natural_frame(900 + i) for i in range(5)]),
        ("Control: white noise (old benchmark 'genuine')", [white_noise_frame(950 + i) for i in range(5)]),
    ]
    for label, frames in controls:
        _, resp = api.run_verification(frames, live_timestamps(7), sealed=True)
        rows.append(_scenario_row(label, "Control", "—", resp))
    write_csv(rows, "s2_attack_scenarios.csv")
    return rows


def _scenario_row(label: str, attack_class: str, expected: str, resp: dict) -> dict:
    scores = resp.get("detection_scores") or {}
    return {
        "scenario": label,
        "attack_class": attack_class,
        "expected": expected,
        "decision": "ACCEPT" if resp["accepted"] else "REJECT",
        "stopped_by": stopped_by(resp),
        "channel": resp.get("channel"),
        **{f"score_{m}": (round(scores[m], 3) if m in scores else None) for m in MODULES},
        "fused_score": None if resp.get("fused_score") is None else round(resp["fused_score"], 3),
        "server_ms": round(resp["timing_ms"].get("total_ms", 0.0), 2),
    }


# ---------------------------------------------------------------------------
# S3. Repeated genuine sessions over the sealed channel
# ---------------------------------------------------------------------------
def repeated_sessions(api) -> list[dict]:
    from detection.replay_detector import store as replay_store

    replay_store.clear()
    rows = []
    for i in range(N_E2E):
        frames = [natural_frame(10_000 + 10 * i + k) for k in range(5)]
        t0 = time.perf_counter()
        _, resp = api.run_verification(frames, live_timestamps(i), sealed=True)
        t1 = time.perf_counter()
        timing = resp["timing_ms"]
        rows.append({
            "run": i,
            "kem_decapsulate_ms": timing["kem_decapsulate_ms"],
            "aead_decrypt_ms": timing["aead_decrypt_ms"],
            "binding_check_ms": timing["binding_check_ms"],
            "liveness_check_ms": timing["liveness_check_ms"],
            "detection_ms": timing["detection_ms"],
            "fusion_ms": timing["fusion_ms"],
            "server_total_ms": timing["total_ms"],
            "end_to_end_ms": (t1 - t0) * 1000,
            "accepted": resp["accepted"],
            "fused_score": resp["fused_score"],
            "vetoed_by": ",".join(resp.get("below_threshold_modules") or []),
        })
    write_csv(rows, "s3_end_to_end.csv")
    return rows


def bench_channel_ops() -> list[dict]:
    """Client-side cost of sealing a typical verification payload."""
    import json

    from crypto.channel import open_payload, seal_payload

    secret, nonce = os.urandom(32), os.urandom(32)
    payload = json.dumps({"frames_b64": [base64.b64encode(os.urandom(60_000)).decode() for _ in range(2)]}).encode()
    aead_nonce, ct = seal_payload(secret, nonce, "sid", payload)
    rows = [
        {"op": f"AES-256-GCM seal ({len(payload) // 1024} kB)", "median_ms": time_ms(lambda: seal_payload(secret, nonce, "sid", payload), 200)[0]},
        {"op": f"AES-256-GCM open ({len(payload) // 1024} kB)", "median_ms": time_ms(lambda: open_payload(secret, nonce, "sid", aead_nonce, ct), 200)[0]},
    ]
    write_csv(rows, "s1_channel_ops.csv")
    return rows


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def plot_scenarios(scen: list[dict]) -> None:
    ran = [s for s in scen if s.get("fused_score") is not None]
    fig, ax = plt.subplots(figsize=(9.5, 0.45 * len(ran) + 1.4))
    mat = np.array([[s[f"score_{m}"] for m in MODULES] + [s["fused_score"]] for s in ran], dtype=float)
    im = ax.imshow(mat, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(MODULES) + 1), ["PAD", "Morph", "Deepfake", "Replay", "Injection", "FUSED"], fontsize=9)
    ax.set_yticks(range(len(ran)), [f"{s['scenario'][:46]}  → {s['decision']}" for s in ran], fontsize=8)
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            ax.text(j, i, f"{mat[i, j]:.2f}", ha="center", va="center", fontsize=8)
    ax.axvline(len(MODULES) - 0.5, color="black", lw=1.2)
    fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02, label="Score (0 = attack, 1 = genuine)")
    ax.set_title("Detector scores for submissions that passed the channel and binding checks", fontsize=10)
    fig.tight_layout()
    fig.savefig(FIG / "fig_r3_detector_heatmap.png", dpi=300)
    plt.close(fig)


def plot_e2e(e2e: list[dict]) -> None:
    med = lambda k: statistics.median(r[k] for r in e2e)  # noqa: E731
    stages = [
        ("ML-KEM-768 decapsulation", med("kem_decapsulate_ms"), "#2a6fbb"),
        ("AES-256-GCM decrypt", med("aead_decrypt_ms"), "#5b8fd1"),
        ("Binding checks (ML-DSA verify, nonce, time, hash)", med("binding_check_ms"), "#8fb3e0"),
        ("Liveness challenge (MediaPipe motion)", med("liveness_check_ms"), "#c9a227"),
        ("AI detection (5 modules)", med("detection_ms"), "#e08a2c"),
        ("Fusion", med("fusion_ms"), "#f2c18d"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.6), gridspec_kw={"width_ratios": [1.4, 1]})
    ax = axes[0]
    left = 0
    for name, v, c in stages:
        ax.barh([0], [v], left=left, color=c, label=f"{name}: {v:.3f} ms")
        left += v
    ax.set_yticks([])
    ax.set_xlabel("Median server-side time per verification (ms)")
    ax.set_title("(a) Where the server's time goes")
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.25), ncol=2)
    ax.spines[["top", "right", "left"]].set_visible(False)

    ax = axes[1]
    ax.boxplot([[r["end_to_end_ms"] for r in e2e], [r["server_total_ms"] for r in e2e]],
               tick_labels=["Client end-to-end\n(4 requests, sealed)", "Server pipeline\nonly"])
    ax.set_ylabel("Latency (ms)")
    ax.set_title(f"(b) Latency distribution, n={len(e2e)}")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "fig_r4_latency_breakdown.png", dpi=300)
    plt.close(fig)


def plot_samples(scen: list[dict]) -> None:
    from client_demo.frame_utils import load_attack_file

    decisions = {s["scenario"]: s for s in scen}
    tiles = [(label, filename) for label, filename, tamper, _, _ in demo_scenarios() if tamper is None]
    fig, axes = plt.subplots(1, len(tiles), figsize=(2.0 * len(tiles), 2.6))
    for ax, (label, filename) in zip(axes, tiles):
        frames, _ = load_attack_file(REPO / "demo_assets" / "attacks" / filename)
        ax.imshow(frames[0])
        s = decisions[label]
        color = "#23864a" if s["decision"] == "ACCEPT" else "#b3261e"
        ax.set_title(label.replace(" presentation attack", "\npresentation attack").replace(" of the", "\nof the"), fontsize=7)
        ax.set_xlabel(f"{s['decision']}\n{s['stopped_by'].replace('AI: ', '').replace('_', ' ')}", fontsize=7, color=color)
        ax.set_xticks([])
        ax.set_yticks([])
    fig.tight_layout()
    fig.savefig(FIG / "fig_r6_demo_samples.png", dpi=300)
    plt.close(fig)


def main() -> None:
    import logging

    logging.disable(logging.WARNING)
    prim = bench_primitives()
    plot_primitives(prim)
    channel_ops = bench_channel_ops()
    api = in_process_client()
    scen = scenario_matrix(api)
    plot_scenarios(scen)
    plot_samples(scen)
    e2e = repeated_sessions(api)
    plot_e2e(e2e)
    summary = {k: {"median": statistics.median(r[k] for r in e2e), "p95": float(np.percentile([r[k] for r in e2e], 95))}
               for k in e2e[0] if k.endswith("_ms")}
    summary["accept_rate"] = sum(r["accepted"] for r in e2e) / len(e2e)
    summary["vetoes"] = [r["vetoed_by"] for r in e2e if not r["accepted"]]
    (DATA / "s3_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({"channel_ops": channel_ops, "scenarios": scen, "e2e_summary": summary}, indent=2, default=str))


if __name__ == "__main__":
    main()
