"""Quantum threat-model and quantum-entropy experiments for the final report.

Three circuits, each run on an ideal Aer simulator and on a noisy Aer
simulator (depolarizing gate noise + readout error), plus a noise sweep:

  Q1. Shor's order-finding for N = 15, a = 7 (the attack that breaks
      RSA-3072 / ECDSA-P256, i.e. the classical baseline in crypto/).
  Q2. Grover search over a 4-qubit key space (the attack that halves the
      security of AES-256 / SHA-256 used for the channel and evidence hash).
  Q3. An 8-qubit Hadamard QRNG used to draw a 256-bit session nonce
      (a quantum-entropy source for binding/session_binding.py's nonce).

Outputs go to report/figures and report/data. Run with a Python that has
qiskit==1.3.2, qiskit-aer==0.15.1, matplotlib, pylatexenc installed.
"""
from __future__ import annotations

import csv
import json
import math
from fractions import Fraction
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import QFT
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error

ROOT = Path(__file__).resolve().parents[1]
FIG = ROOT / "figures"
DATA = ROOT / "data"
FIG.mkdir(parents=True, exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)

SHOTS = 8192
SEED = 2026
BASIS = ["cx", "rz", "sx", "x", "id"]

plt.rcParams.update({"font.family": "serif", "font.size": 10})


def noise_model(p2: float, readout: float | None = None) -> NoiseModel:
    """1q depolarizing = p2/10, 2q depolarizing = p2, symmetric readout flip."""
    nm = NoiseModel()
    if p2 > 0:
        nm.add_all_qubit_quantum_error(depolarizing_error(p2 / 10, 1), ["rz", "sx", "x"])
        nm.add_all_qubit_quantum_error(depolarizing_error(p2, 2), ["cx"])
    r = p2 * 2 if readout is None else readout
    if r > 0:
        nm.add_all_qubit_readout_error(ReadoutError([[1 - r, r], [r, 1 - r]]))
    return nm


def run(qc: QuantumCircuit, p2: float = 0.0, readout: float | None = None) -> dict[str, int]:
    sim = AerSimulator(noise_model=noise_model(p2, readout), seed_simulator=SEED)
    tqc = transpile(qc, basis_gates=BASIS, optimization_level=3, seed_transpiler=SEED)
    return sim.run(tqc, shots=SHOTS).result().get_counts()


def circuit_stats(qc: QuantumCircuit) -> dict:
    tqc = transpile(qc, basis_gates=BASIS, optimization_level=3, seed_transpiler=SEED)
    ops = tqc.count_ops()
    return {
        "qubits": qc.num_qubits,
        "clbits": qc.num_clbits,
        "logical_depth": qc.decompose().depth(),
        "transpiled_depth": tqc.depth(),
        "cx_count": int(ops.get("cx", 0)),
        "single_qubit_gates": int(sum(v for k, v in ops.items() if k in ("rz", "sx", "x"))),
    }


# ---------------------------------------------------------------------------
# Q1. Shor order finding, N = 15, a = 7
# ---------------------------------------------------------------------------
N_SHOR, A_SHOR, N_COUNT = 15, 7, 4


def c_amod15(a: int, power: int):
    u = QuantumCircuit(4)
    for _ in range(power):
        if a in (2, 13):
            u.swap(2, 3); u.swap(1, 2); u.swap(0, 1)
        if a in (7, 8):
            u.swap(0, 1); u.swap(1, 2); u.swap(2, 3)
        if a in (4, 11):
            u.swap(1, 3); u.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                u.x(q)
    g = u.to_gate()
    g.name = f"{a}^{power} mod 15"
    return g.control()


def shor_circuit() -> QuantumCircuit:
    qc = QuantumCircuit(N_COUNT + 4, N_COUNT, name="Shor N=15")
    qc.h(range(N_COUNT))
    qc.x(N_COUNT)  # work register |0001> = 1
    for q in range(N_COUNT):
        qc.append(c_amod15(A_SHOR, 2**q), [q] + [N_COUNT + i for i in range(4)])
    qc.append(QFT(N_COUNT, inverse=True, do_swaps=True, name="QFT†"), range(N_COUNT))
    qc.measure(range(N_COUNT), range(N_COUNT))
    return qc


def shor_success(counts: dict[str, int]) -> float:
    ok = 0
    for bits, c in counts.items():
        phase = int(bits, 2) / 2**N_COUNT
        r = Fraction(phase).limit_denominator(N_SHOR).denominator
        if r % 2 == 0 and pow(A_SHOR, r, N_SHOR) == 1:
            x = pow(A_SHOR, r // 2, N_SHOR)
            f = {math.gcd(x - 1, N_SHOR), math.gcd(x + 1, N_SHOR)}
            if f & {3, 5}:
                ok += c
    return ok / sum(counts.values())


# ---------------------------------------------------------------------------
# Q2. Grover key search, 4-qubit key space, marked key = 1011
# ---------------------------------------------------------------------------
GROVER_N, GROVER_KEY = 4, "1011"


def grover_circuit(iterations: int | None = None) -> QuantumCircuit:
    n = GROVER_N
    k = iterations if iterations is not None else math.floor(math.pi / 4 * math.sqrt(2**n))
    qc = QuantumCircuit(n, n, name=f"Grover n={n}")
    qc.h(range(n))
    for _ in range(k):
        # Oracle: phase-flip |GROVER_KEY>  (qubit 0 = least significant bit)
        zeros = [i for i, b in enumerate(reversed(GROVER_KEY)) if b == "0"]
        if zeros:
            qc.x(zeros)
        qc.h(n - 1); qc.mcx(list(range(n - 1)), n - 1); qc.h(n - 1)
        if zeros:
            qc.x(zeros)
        qc.barrier()
        # Diffuser
        qc.h(range(n)); qc.x(range(n))
        qc.h(n - 1); qc.mcx(list(range(n - 1)), n - 1); qc.h(n - 1)
        qc.x(range(n)); qc.h(range(n))
        qc.barrier()
    qc.measure(range(n), range(n))
    return qc


def grover_success(counts: dict[str, int]) -> float:
    return counts.get(GROVER_KEY, 0) / sum(counts.values())


# ---------------------------------------------------------------------------
# Q3. QRNG for the 256-bit session nonce
# ---------------------------------------------------------------------------
QRNG_N = 8


def qrng_circuit() -> QuantumCircuit:
    qc = QuantumCircuit(QRNG_N, QRNG_N, name="QRNG")
    qc.h(range(QRNG_N))
    qc.measure(range(QRNG_N), range(QRNG_N))
    return qc


def qrng_stats(counts: dict[str, int]) -> dict:
    total = sum(counts.values())
    probs = np.array([counts.get(format(i, f"0{QRNG_N}b"), 0) / total for i in range(2**QRNG_N)])
    p_one = sum(c * b.count("1") for b, c in counts.items()) / (total * QRNG_N)
    expected = total / 2**QRNG_N
    chi2 = float(sum((counts.get(format(i, f"0{QRNG_N}b"), 0) - expected) ** 2 / expected for i in range(2**QRNG_N)))
    return {
        "min_entropy_bits_per_byte": float(-math.log2(probs.max())),
        "shannon_entropy_bits_per_byte": float(-(probs[probs > 0] * np.log2(probs[probs > 0])).sum()),
        "bit_bias_p1": p_one,
        "chi2_255dof": chi2,
    }


def qrng_nonce(p2: float = 0.0) -> bytes:
    sim = AerSimulator(noise_model=noise_model(p2), seed_simulator=SEED)
    tqc = transpile(qrng_circuit(), basis_gates=BASIS)
    mem = sim.run(tqc, shots=32, memory=True).result().get_memory()
    return bytes(int(b, 2) for b in mem)


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def draw(qc: QuantumCircuit, name: str, fold: int = -1) -> None:
    fig = qc.draw(output="mpl", fold=fold, style="bw")
    fig.savefig(FIG / name, dpi=300, bbox_inches="tight")
    plt.close(fig)


def histogram_pair(ideal: dict, noisy: dict, title: str, name: str, highlight: set[str], width: int) -> None:
    keys = [format(i, f"0{width}b") for i in range(2**width)]
    tot_i, tot_n = sum(ideal.values()), sum(noisy.values())
    pi = [ideal.get(k, 0) / tot_i for k in keys]
    pn = [noisy.get(k, 0) / tot_n for k in keys]
    x = np.arange(len(keys))
    fig, ax = plt.subplots(figsize=(8, 3.4))
    ax.bar(x - 0.2, pi, 0.4, label="Ideal (Aer statevector sampling)", color="#2a6fbb")
    ax.bar(x + 0.2, pn, 0.4, label="Noisy (p₂=1%, p₁=0.1%, readout 2%)", color="#e08a2c")
    for i, k in enumerate(keys):
        if k in highlight:
            ax.axvspan(i - 0.5, i + 0.5, color="#2a9d55", alpha=0.10, lw=0)
    ax.set_xticks(x, keys, rotation=90 if width > 3 else 0, fontsize=8)
    ax.set_ylabel("Probability")
    ax.set_xlabel("Measured bitstring")
    ax.set_title(title)
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=300)
    plt.close(fig)


def main() -> None:
    shor, grover, qrng = shor_circuit(), grover_circuit(), qrng_circuit()
    draw(shor, "fig_q1_shor_circuit.png")
    draw(grover, "fig_q2_grover_circuit.png", fold=34)
    draw(qrng, "fig_q3_qrng_circuit.png")

    stats = {"shor_N15": circuit_stats(shor), "grover_4q": circuit_stats(grover), "qrng_8q": circuit_stats(qrng)}

    # Ideal vs. noisy (p2 = 1%)
    P2_REF = 0.01
    results = {}
    for label, qc in (("shor_N15", shor), ("grover_4q", grover), ("qrng_8q", qrng)):
        results[label] = {"ideal": run(qc, 0.0), "noisy": run(qc, P2_REF)}

    histogram_pair(results["shor_N15"]["ideal"], results["shor_N15"]["noisy"],
                   "Shor order-finding (N=15, a=7): counting-register distribution",
                   "fig_q4_shor_histogram.png", {"0000", "0100", "1000", "1100"}, N_COUNT)
    histogram_pair(results["grover_4q"]["ideal"], results["grover_4q"]["noisy"],
                   f"Grover key search (n=4, key={GROVER_KEY}, 3 iterations)",
                   "fig_q5_grover_histogram.png", {GROVER_KEY}, GROVER_N)

    summary_rows = []
    for label, succ in (("shor_N15", shor_success), ("grover_4q", grover_success)):
        summary_rows.append({
            "circuit": label, **stats[label],
            "success_ideal": succ(results[label]["ideal"]),
            "success_noisy_p2_1pct": succ(results[label]["noisy"]),
        })
    qi, qn = qrng_stats(results["qrng_8q"]["ideal"]), qrng_stats(results["qrng_8q"]["noisy"])
    summary_rows.append({"circuit": "qrng_8q", **stats["qrng_8q"],
                         "success_ideal": qi["min_entropy_bits_per_byte"] / 8,
                         "success_noisy_p2_1pct": qn["min_entropy_bits_per_byte"] / 8})
    with open(DATA / "quantum_circuit_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        w.writeheader(); w.writerows(summary_rows)

    # Noise sweep
    sweep = [0.0, 0.001, 0.0025, 0.005, 0.01, 0.02, 0.03, 0.05]
    sweep_rows = []
    for p2 in sweep:
        qs = qrng_stats(run(qrng, p2))
        sweep_rows.append({
            "p2": p2,
            "shor_success": shor_success(run(shor, p2)),
            "grover_success": grover_success(run(grover, p2)),
            "qrng_min_entropy_per_bit": qs["min_entropy_bits_per_byte"] / 8,
            "qrng_bit_bias_p1": qs["bit_bias_p1"],
        })
    with open(DATA / "quantum_noise_sweep.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sweep_rows[0].keys()))
        w.writeheader(); w.writerows(sweep_rows)

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    xs = [r["p2"] * 100 for r in sweep_rows]
    ax.plot(xs, [r["shor_success"] for r in sweep_rows], "o-", label="Shor N=15: P(correct factors)", color="#2a6fbb")
    ax.plot(xs, [r["grover_success"] for r in sweep_rows], "s-", label="Grover n=4: P(key found)", color="#e08a2c")
    ax.plot(xs, [r["qrng_min_entropy_per_bit"] for r in sweep_rows], "^-", label="QRNG: min-entropy / bit", color="#2a9d55")
    ax.axhline(1 / 16, ls=":", color="grey", lw=1)
    ax.text(2.5, 1 / 16 - 0.045, "uniform random outcome (1/16)", ha="center", fontsize=8, color="grey")
    ax.set_xlabel("Two-qubit depolarizing error p₂ (%)  [p₁ = p₂/10, readout = 2·p₂]")
    ax.set_ylabel("Probability / entropy")
    ax.set_ylim(0, 1.05)
    ax.set_title("Effect of hardware noise on the quantum circuits")
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "fig_q6_noise_sweep.png", dpi=300)
    plt.close(fig)

    # Asymmetric readout (T1-like decay: P(read 0 | 1) = 4%, P(read 1 | 0) = 1%)
    # biases a QRNG, unlike the symmetric noise above.
    asym = NoiseModel()
    asym.add_all_qubit_readout_error(ReadoutError([[0.99, 0.01], [0.04, 0.96]]))
    qa_counts = AerSimulator(noise_model=asym, seed_simulator=SEED).run(
        transpile(qrng, basis_gates=BASIS), shots=SHOTS).result().get_counts()
    qa = qrng_stats(qa_counts)

    nonce = qrng_nonce()
    with open(DATA / "qrng_sample.json", "w") as f:
        json.dump({"nonce_hex": nonce.hex(), "qrng_ideal": qi, "qrng_noisy_p2_1pct": qn,
                   "qrng_asymmetric_readout": qa}, f, indent=2)

    print(json.dumps({"stats": stats, "summary": summary_rows, "sweep": sweep_rows, "qrng": {"ideal": qi, "noisy": qn, "asym": qa}}, indent=2))


if __name__ == "__main__":
    main()
