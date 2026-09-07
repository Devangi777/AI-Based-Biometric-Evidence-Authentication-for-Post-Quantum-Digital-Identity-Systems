"""Smoke tests for evaluation/benchmark.py - verifies the harness produces
well-formed output with small iteration counts, without needing liboqs
(the PQC portion self-skips, matching production behavior outside Docker -
see the module docstring) or a running server (throughput is opt-out here).
"""
from __future__ import annotations

from evaluation.benchmark import benchmark_crypto, benchmark_detection, benchmark_resource_overhead


def test_benchmark_crypto_returns_classical_baseline_rows_even_without_oqs():
    rows = benchmark_crypto(n=2)
    ops = {r["op"] for r in rows}
    # RSA/ECDSA rows always run (no liboqs dependency); ML-KEM/ML-DSA rows
    # are present only if liboqs is available in this environment.
    assert {"RSA-3072.encrypt", "RSA-3072.decrypt", "ECDSA-P256.sign", "ECDSA-P256.verify"} <= ops
    for row in rows:
        assert row["n"] >= 1


def test_benchmark_detection_returns_latency_and_accuracy_rows():
    latency_rows, accuracy_rows = benchmark_detection(n=2)
    latency_modules = {r["module"] for r in latency_rows}
    assert latency_modules == {"presentation_attack", "morph", "deepfake", "injection", "replay"}
    for row in latency_rows:
        assert row["mean_ms"] >= 0

    accuracy_modules = {r["module"] for r in accuracy_rows}
    assert accuracy_modules == {"presentation_attack", "morph", "deepfake", "injection"}
    for row in accuracy_rows:
        assert 0.0 <= row["accuracy"] <= 1.0
        assert row["is_mock"] is True


def test_benchmark_resource_overhead_returns_both_phases():
    rows = benchmark_resource_overhead(n=2)
    phases = {r["phase"] for r in rows}
    assert phases == {"crypto", "detection"}
    for row in rows:
        assert row["rss_bytes_delta"] is not None
