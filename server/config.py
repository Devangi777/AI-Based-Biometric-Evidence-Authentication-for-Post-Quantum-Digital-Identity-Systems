"""Central configuration, loaded from environment variables / .env.

Mirrors .env.example - every field here has the same default as that file so
the app runs with sane behavior even if .env is missing.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- PQC algorithm selection (Section 5) ---
    kem_alg: str = "ML-KEM-768"
    sig_alg: str = "ML-DSA-65"
    enable_classical_baseline: bool = True

    # --- Session binding / freshness (Section 7) ---
    freshness_window_seconds: int = 30
    nonce_bytes: int = 32

    # --- Detection thresholds (Section 6.6 fusion) ---
    threshold_presentation_attack: float = 0.5
    threshold_morph: float = 0.5
    threshold_deepfake: float = 0.5
    threshold_replay: float = 0.5
    threshold_injection: float = 0.5

    weight_presentation_attack: float = 0.25
    weight_morph: float = 0.20
    weight_deepfake: float = 0.25
    weight_replay: float = 0.15
    weight_injection: float = 0.15

    fusion_accept_threshold: float = 0.6

    # --- Detection model mode ---
    detection_mode: str = "pretrained"  # "pretrained" | "mock"
    detector_device: str = "cpu"

    # --- Server ---
    server_host: str = "0.0.0.0"
    server_port: int = 8000
    demo_mode: bool = False  # enables POST /demo/reset-replay-store for rehearsals

    # --- Replay detector store ---
    replay_hash_window_seconds: int = 86400

    # --- Client demo ---
    api_base_url: str = "http://localhost:8000"


settings = Settings()
