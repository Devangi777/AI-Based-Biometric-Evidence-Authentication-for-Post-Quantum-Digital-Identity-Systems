"""Evaluation harness - spec Section 8.

Produces the required results as CSV + basic charts under evaluation/results/
(gitignored - regenerate locally, don't commit results):
  1. PQC vs. classical crypto overhead: op latency + payload size,
     ML-KEM-768/ML-DSA-65 vs. RSA-3072/ECDSA-P256, isolated from AI cost.
  2. AI detection latency per module (mock mode in this environment - see
     detection/README-models.md).
  3. Detection "accuracy" per module on a small synthetic/demo_assets-backed
     sample set - explicitly NOT a real accuracy result without labeled
     research datasets; see the loud caveat this script prints and writes
     into the CSV header comment.
  4. Throughput (verifications/sec vs. concurrent sessions) against a
     running server - skipped with a clear message if the server (Docker,
     per SETUP.md) isn't reachable, rather than failing the whole run.
  5. CPU/memory overhead (process-level, via psutil) during the crypto and
     detection benchmarks.

Run: `python -m evaluation.benchmark` (from the repo root, with either the
native venv per SETUP.md Step 1, or `docker compose exec server python -m
evaluation.benchmark`).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import psutil

from evaluation.metrics import evaluate

logger = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).resolve().parent / "results"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
@dataclass
class TimingStats:
    n: int
    mean_ms: float
    median_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float


def _time_it(fn, n: int) -> TimingStats:
    samples_ms = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples_ms.append((time.perf_counter() - t0) * 1000)
    return TimingStats(
        n=n,
        mean_ms=statistics.mean(samples_ms),
        median_ms=statistics.median(samples_ms),
        stdev_ms=statistics.stdev(samples_ms) if n > 1 else 0.0,
        min_ms=min(samples_ms),
        max_ms=max(samples_ms),
    )


def _process_snapshot() -> dict:
    proc = psutil.Process()
    cpu_times = proc.cpu_times()
    mem = proc.memory_info()
    return {"cpu_user_s": cpu_times.user, "cpu_system_s": cpu_times.system, "rss_bytes": mem.rss}


def _synthetic_frame(rng: np.random.Generator) -> np.ndarray:
    return rng.integers(0, 256, size=(200, 200, 3), dtype=np.uint8)


def _write_csv(rows: list[dict], path: Path) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        logger.warning("No rows to write for %s - skipping", path)
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Wrote %s (%d rows)", path, len(rows))


# --------------------------------------------------------------------------
# 1. PQC vs. classical crypto overhead
# --------------------------------------------------------------------------
def benchmark_crypto(n: int = 30) -> list[dict]:
    rows: list[dict] = []

    try:
        from crypto.kem import ServerKemSession, client_encapsulate, kem_details
        from crypto.signature import SignerIdentity, build_binding_payload, sig_details, verify as sig_verify

        kem_alg = "ML-KEM-768"
        sig_alg = "ML-DSA-65"

        with ServerKemSession(alg=kem_alg) as server:
            server_pk = server.generate_keypair()

            def _do_encap():
                client_encapsulate(server_pk, alg=kem_alg)

            rows.append({"op": "ML-KEM-768.encapsulate", **asdict(_time_it(_do_encap, n))})

            ciphertext, _ = client_encapsulate(server_pk, alg=kem_alg)

            def _do_decap():
                server.decapsulate(ciphertext)

            rows.append({"op": "ML-KEM-768.decapsulate", **asdict(_time_it(_do_decap, n))})

        with SignerIdentity(alg=sig_alg) as signer:
            message = build_binding_payload(b"\x00" * 32, b"\x01" * 32, "2026-01-01T00:00:00Z", "7")

            def _do_sign():
                signer.sign(message)

            rows.append({"op": "ML-DSA-65.sign", **asdict(_time_it(_do_sign, n))})

            signature = signer.sign(message)

            def _do_verify():
                sig_verify(message, signature, signer.public_key, alg=sig_alg)

            rows.append({"op": "ML-DSA-65.verify", **asdict(_time_it(_do_verify, n))})

        kd = kem_details(kem_alg)
        sd = sig_details(sig_alg)
        rows.append({"op": "ML-KEM-768.public_key_bytes", "n": 1, "mean_ms": kd.get("length_public_key", 0), "median_ms": 0, "stdev_ms": 0, "min_ms": 0, "max_ms": 0})
        rows.append({"op": "ML-KEM-768.ciphertext_bytes", "n": 1, "mean_ms": kd.get("length_ciphertext", 0), "median_ms": 0, "stdev_ms": 0, "min_ms": 0, "max_ms": 0})
        rows.append({"op": "ML-DSA-65.signature_bytes", "n": 1, "mean_ms": sd.get("length_signature", 0), "median_ms": 0, "stdev_ms": 0, "min_ms": 0, "max_ms": 0})
    except Exception as exc:
        logger.warning("Skipping PQC benchmarks - liboqs unavailable in this environment (%s). See SETUP.md.", exc)

    from crypto import classical_baseline

    rsa_private, rsa_public = classical_baseline.rsa_generate_keypair()
    payload = b"\x00" * 32  # AES-256-key-sized payload, the classical analogue of an ML-KEM shared secret

    def _do_rsa_encrypt():
        classical_baseline.rsa_encrypt(rsa_public, payload)

    rows.append({"op": "RSA-3072.encrypt", **asdict(_time_it(_do_rsa_encrypt, n))})

    rsa_ciphertext = classical_baseline.rsa_encrypt(rsa_public, payload)

    def _do_rsa_decrypt():
        classical_baseline.rsa_decrypt(rsa_private, rsa_ciphertext)

    rows.append({"op": "RSA-3072.decrypt", **asdict(_time_it(_do_rsa_decrypt, n))})

    ec_private, ec_public = classical_baseline.ecdsa_generate_keypair()
    ec_message = b"evidence-hash-nonce-timestamp"

    def _do_ecdsa_sign():
        classical_baseline.ecdsa_sign(ec_private, ec_message)

    rows.append({"op": "ECDSA-P256.sign", **asdict(_time_it(_do_ecdsa_sign, n))})

    ec_signature = classical_baseline.ecdsa_sign(ec_private, ec_message)

    def _do_ecdsa_verify():
        classical_baseline.ecdsa_verify(ec_public, ec_message, ec_signature)

    rows.append({"op": "ECDSA-P256.verify", **asdict(_time_it(_do_ecdsa_verify, n))})
    rows.append({"op": "RSA-3072.public_key_bytes", "n": 1, "mean_ms": classical_baseline.public_key_size_bytes(rsa_public), "median_ms": 0, "stdev_ms": 0, "min_ms": 0, "max_ms": 0})
    rows.append({"op": "ECDSA-P256.public_key_bytes", "n": 1, "mean_ms": classical_baseline.public_key_size_bytes(ec_public), "median_ms": 0, "stdev_ms": 0, "min_ms": 0, "max_ms": 0})

    return rows


# --------------------------------------------------------------------------
# 2 & 3. Detection latency and (caveated) accuracy
# --------------------------------------------------------------------------
def benchmark_detection(n: int = 10) -> tuple[list[dict], list[dict]]:
    from detection.deepfake_detector import DeepfakeDetector
    from detection.injection_detector import InjectionDetector
    from detection.morph_detector import MorphDetector
    from detection.presentation_attack import PresentationAttackDetector
    from detection.replay_detector import ReplayDetector

    rng = np.random.default_rng(42)
    detectors = {
        "presentation_attack": PresentationAttackDetector(mode="mock"),
        "morph": MorphDetector(mode="mock"),
        "deepfake": DeepfakeDetector(mode="mock"),
        "injection": InjectionDetector(mode="mock"),
    }

    latency_rows = []
    for name, detector in detectors.items():
        frame = _synthetic_frame(rng)

        def _predict():
            detector.predict(frame)

        latency_rows.append({"module": name, **asdict(_time_it(_predict, n))})

    replay = ReplayDetector()

    def _replay_check():
        replay.check_and_record(_synthetic_frame(rng), session_id="bench")

    latency_rows.append({"module": "replay", **asdict(_time_it(_replay_check, n))})

    # Caveated pseudo-accuracy: synthetic "genuine" frames (random noise,
    # matching the mock heuristics' calibration target) vs. a crude
    # synthetic "attack" proxy (flat/low-variance frames, standing in for a
    # blurry recapture). This is a pipeline smoke test, NOT a meaningful
    # detection-accuracy number - see detection/README-models.md and the
    # printed warning in main().
    accuracy_rows = []
    genuine_frames = [_synthetic_frame(rng) for _ in range(8)]
    attack_frames = [np.full((200, 200, 3), 128, dtype=np.uint8) for _ in range(8)]
    labels = [True] * len(genuine_frames) + [False] * len(attack_frames)

    for name in ("presentation_attack", "morph", "deepfake", "injection"):
        detector = detectors[name]
        scores = [detector.predict(f).score for f in genuine_frames + attack_frames]
        metrics = evaluate(scores, labels, threshold=0.5)
        accuracy_rows.append({"module": name, "is_mock": True, **metrics.as_dict()})

    return latency_rows, accuracy_rows


# --------------------------------------------------------------------------
# 4. Throughput against a running server (optional - needs Docker up)
# --------------------------------------------------------------------------
async def _throughput_worker(client, base_url: str) -> bool:
    try:
        resp = await client.post(f"{base_url}/session/start", timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


async def _run_throughput_round(base_url: str, concurrency: int) -> float:
    import httpx

    async with httpx.AsyncClient() as client:
        t0 = time.perf_counter()
        results = await asyncio.gather(*[_throughput_worker(client, base_url) for _ in range(concurrency)])
        elapsed = time.perf_counter() - t0
    ok = sum(results)
    return ok / elapsed if elapsed > 0 else 0.0


def benchmark_throughput(base_url: str = "http://localhost:8000", concurrency_levels: tuple[int, ...] = (1, 2, 4, 8)) -> list[dict]:
    import httpx

    try:
        httpx.get(f"{base_url}/health", timeout=5)
    except Exception as exc:
        logger.warning("Skipping throughput benchmark - server unreachable at %s (%s). Start it per SETUP.md.", base_url, exc)
        return []

    rows = []
    for concurrency in concurrency_levels:
        req_per_sec = asyncio.run(_run_throughput_round(base_url, concurrency))
        rows.append({"concurrency": concurrency, "sessions_per_sec": req_per_sec})
    return rows


# --------------------------------------------------------------------------
# 5. CPU/memory overhead
# --------------------------------------------------------------------------
def benchmark_resource_overhead(n: int = 20) -> list[dict]:
    rows = []

    before = _process_snapshot()
    benchmark_crypto(n=n)
    after = _process_snapshot()
    rows.append(
        {
            "phase": "crypto",
            "cpu_user_s_delta": after["cpu_user_s"] - before["cpu_user_s"],
            "cpu_system_s_delta": after["cpu_system_s"] - before["cpu_system_s"],
            "rss_bytes_delta": after["rss_bytes"] - before["rss_bytes"],
        }
    )

    before = _process_snapshot()
    benchmark_detection(n=n)
    after = _process_snapshot()
    rows.append(
        {
            "phase": "detection",
            "cpu_user_s_delta": after["cpu_user_s"] - before["cpu_user_s"],
            "cpu_system_s_delta": after["cpu_system_s"] - before["cpu_system_s"],
            "rss_bytes_delta": after["rss_bytes"] - before["rss_bytes"],
        }
    )
    return rows


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------
def _plot_latency_bar(crypto_rows: list[dict], detection_rows: list[dict], out_path: Path) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed - skipping charts")
        return

    timed = [r for r in crypto_rows if r.get("n", 0) and r["n"] > 1] + [r for r in detection_rows if r.get("n", 0) and r["n"] > 1]
    if not timed:
        return
    labels = [r["op"] if "op" in r else r["module"] for r in timed]
    values = [r["mean_ms"] for r in timed]

    fig, ax = plt.subplots(figsize=(10, max(4, 0.4 * len(labels))))
    ax.barh(labels, values)
    ax.set_xlabel("Mean latency (ms)")
    ax.set_title("Per-stage latency: crypto ops vs. AI detection modules")
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    plt.close(fig)
    logger.info("Wrote %s", out_path)


def _plot_throughput_line(throughput_rows: list[dict], out_path: Path) -> None:
    if not throughput_rows:
        return
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed - skipping charts")
        return

    xs = [r["concurrency"] for r in throughput_rows]
    ys = [r["sessions_per_sec"] for r in throughput_rows]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(xs, ys, marker="o")
    ax.set_xlabel("Concurrent sessions")
    ax.set_ylabel("Sessions/sec")
    ax.set_title("Throughput vs. concurrency")
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    plt.close(fig)
    logger.info("Wrote %s", out_path)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Section 8 evaluation harness")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--crypto-iterations", type=int, default=30)
    parser.add_argument("--detection-iterations", type=int, default=10)
    parser.add_argument("--skip-throughput", action="store_true")
    args = parser.parse_args()

    print(
        "NOTE: detection accuracy numbers below use synthetic placeholder "
        "samples (random noise vs. flat frames), not a labeled research "
        "dataset - they exercise the pipeline end-to-end, they are NOT a "
        "real accuracy result. See detection/README-models.md."
    )

    crypto_rows = benchmark_crypto(n=args.crypto_iterations)
    _write_csv(crypto_rows, RESULTS_DIR / "crypto_overhead.csv")

    detection_latency_rows, detection_accuracy_rows = benchmark_detection(n=args.detection_iterations)
    _write_csv(detection_latency_rows, RESULTS_DIR / "detection_latency.csv")
    _write_csv(detection_accuracy_rows, RESULTS_DIR / "detection_accuracy_SYNTHETIC.csv")

    resource_rows = benchmark_resource_overhead(n=args.detection_iterations)
    _write_csv(resource_rows, RESULTS_DIR / "resource_overhead.csv")

    throughput_rows = [] if args.skip_throughput else benchmark_throughput(base_url=args.base_url)
    _write_csv(throughput_rows, RESULTS_DIR / "throughput.csv")

    _plot_latency_bar(crypto_rows, detection_latency_rows, RESULTS_DIR / "latency_per_stage.png")
    _plot_throughput_line(throughput_rows, RESULTS_DIR / "throughput_vs_concurrency.png")

    print(f"Results written to {RESULTS_DIR}")


if __name__ == "__main__":
    main()
