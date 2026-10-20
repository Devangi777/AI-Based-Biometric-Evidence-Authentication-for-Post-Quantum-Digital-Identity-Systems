"""Pre-demo self-check: run every demo scenario against the running server
through the same client code the Streamlit app uses, and confirm each one
gets the expected decision for the expected reason.

    uvicorn server.main:app --port 8000      # in another terminal
    python scripts/make_demo_assets.py       # once, if demo_assets/attacks/ is empty
    python scripts/demo_check.py             # add --explain to print each decision's reason

Exits non-zero if any scenario does not behave as expected. Resets the
server's replay memory first (needs DEMO_MODE=true on the server) so the
genuine sample is "new" again; otherwise run this right after a server start.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from client_demo.api_client import ApiError, can_seal, health, reset_replay_store, run_verification  # noqa: E402
from client_demo.frame_utils import load_attack_file  # noqa: E402

ATTACKS = REPO / "demo_assets" / "attacks"

# (label, sample file, tamper mode, expected decision, check/module expected to fire)
SCENARIOS = [
    ("Genuine capture", "genuine_sample.jpg", None, "ACCEPT", None),
    ("Replay of the accepted capture", "replay_sample.jpg", None, "REJECT", "replay"),
    ("Printed-photo presentation attack", "presentation_photo.jpg", None, "REJECT", "presentation_attack"),
    ("Screen-replay presentation attack", "presentation_screen_replay.mp4", None, "REJECT", "presentation_attack"),
    ("Face morph", "morphed_face.jpg", None, "REJECT", "morph"),
    ("Deepfake video", "deepfake_sample.mp4", None, "REJECT", "deepfake"),
    ("Injected virtual-camera stream", "injection_sample.mp4", None, "REJECT", "injection"),
    ("Stale evidence", "genuine_sample.jpg", "stale_timestamp", "REJECT", "timestamp_fresh"),
    ("Frames swapped after signing", "genuine_sample.jpg", "swap_frames", "REJECT", "evidence_matches_hash"),
    ("Nonce reuse", "genuine_sample.jpg", "reuse_nonce", "REJECT", "nonce_unused"),
    ("Wrong liveness answer", "genuine_sample.jpg", "wrong_challenge", "REJECT", "challenge_fulfilled"),
    ("Tampered sealed payload", "genuine_sample.jpg", "corrupt_channel", "REJECT", "channel_authentic"),
]


def fired(result: dict) -> list[str]:
    failed_checks = [name for name, ok in result["binding_checks"].items() if not ok]
    return failed_checks or (result.get("below_threshold_modules") or [])


def main() -> int:
    explain = "--explain" in sys.argv
    try:
        info = health()
    except ApiError as exc:
        print(f"Server not reachable: {exc}\nStart it with: uvicorn server.main:app --port 8000")
        return 1
    print(f"Server: {info['status']}  {info['kem_alg']} / {info['sig_alg']}  liboqs_ready={info['liboqs_ready']}")
    print(f"Client channel: {'sealed (ML-KEM + AES-256-GCM)' if can_seal() else 'plaintext (no liboqs on client)'}")
    try:
        reset_replay_store()
    except ApiError:
        print("Note: server not in DEMO_MODE - replay memory not reset; run this right after starting the server.")

    failures = 0
    print(f"\n{'Scenario':36s} {'Decision':8s} {'Expected':8s} {'Caught by':34s} {'ms':>7s}")
    for label, filename, tamper, expected, expected_trigger in SCENARIOS:
        path = ATTACKS / filename
        if not path.exists():
            print(f"{label:36s} MISSING {path.relative_to(REPO)} - run scripts/make_demo_assets.py")
            failures += 1
            continue
        if tamper == "corrupt_channel" and not can_seal():
            print(f"{label:36s} skipped (needs liboqs on the client)")
            continue
        frames, frame_timestamps = load_attack_file(path)
        _, result = run_verification(frames, frame_timestamps, tamper=tamper)
        decision = "ACCEPT" if result["accepted"] else "REJECT"
        triggers = fired(result)
        ok = decision == expected and (expected_trigger is None or expected_trigger in triggers)
        failures += not ok
        total_ms = result["timing_ms"].get("total_ms", 0.0)
        print(f"{label:36s} {decision:8s} {expected:8s} {', '.join(triggers) or '-':34s} {total_ms:7.1f}  {'ok' if ok else 'UNEXPECTED'}")
        if explain and result.get("explanations"):
            print(f"    why: {result['explanations'][0]}")

    print(f"\n{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios behaved as expected.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
