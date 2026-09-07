"""Streamlit demo client - spec Section 12.

Runs NATIVELY on Windows Python (see SETUP.md - webcam access via
streamlit-webrtc is simplest directly on the host OS) and talks to the
Dockerized FastAPI server (server/main.py) over HTTP at API_BASE_URL. All
PQC operations happen server-side (README.md "Assumptions" #2); this app
only computes the SHA-256 evidence hash locally and orchestrates API calls.

Implements both Section 12 demo modes as tabs:
  - Live Capture: real webcam via streamlit-webrtc, full session + liveness
    challenge + verification flow against a live frame.
  - Simulate Attack: loads a bundled file from demo_assets/attacks/ (or an
    uploaded file) and feeds it through the identical pipeline, so the
    audience sees the same crypto+binding+detection flow catch each attack
    type rather than a separate "fake" code path.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from client_demo.api_client import (
    ApiError,
    establish_channel,
    health,
    now_iso,
    session_start,
    sha256_hex,
    sign_evidence,
    verify_evidence,
)
from client_demo.frame_utils import frame_to_b64, frame_to_png_bytes, load_attack_file

load_dotenv()

st.set_page_config(page_title="PQ-Biometric-Auth Demo", layout="wide")

ATTACK_FILES = {
    "Presentation attack (printed photo)": "presentation_photo.jpg",
    "Presentation attack (screen replay)": "presentation_screen_replay.mp4",
    "Face morphing": "morphed_face.jpg",
    "Deepfake": "deepfake_sample.mp4",
    "Replay (resubmitted genuine capture)": "replay_sample.jpg",
    "Injection (virtual camera / screen recording)": "injection_sample.mp4",
}

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "demo_assets" / "attacks"


def _init_state() -> None:
    st.session_state.setdefault("log", [])
    st.session_state.setdefault("session", None)
    st.session_state.setdefault("captured_frame", None)


def _sidebar_health() -> None:
    st.sidebar.header("Server status")
    try:
        info = health()
    except ApiError as exc:
        st.sidebar.error(f"Server unreachable: {exc}")
        st.sidebar.caption("Check docker compose is running - see SETUP.md.")
        return

    if info.get("liboqs_ready"):
        st.sidebar.success(f"Server reachable\n\n{info['kem_alg']} / {info['sig_alg']}")
    else:
        st.sidebar.warning(f"Server reachable, but liboqs not ready:\n\n{info.get('error', 'unknown error')}")


def _start_new_session() -> dict:
    session = session_start()
    establish_channel(session["session_id"])
    st.session_state.session = session
    return session


def _run_pipeline(frames: list, frame_timestamps, challenge_response: str, label: str) -> dict:
    session = st.session_state.session or _start_new_session()
    session_id = session["session_id"]

    evidence_bytes = frame_to_png_bytes(frames[0])
    evidence_hash = sha256_hex(evidence_bytes)
    timestamp = now_iso()

    sign_result = sign_evidence(session_id, evidence_hash, timestamp, challenge_response)
    frames_b64 = [frame_to_b64(f) for f in frames]
    verify_result = verify_evidence(
        session_id,
        evidence_hash,
        timestamp,
        challenge_response,
        sign_result["signature"],
        frames_b64,
        frame_timestamps,
    )

    st.session_state.log.insert(
        0,
        {
            "time": time.strftime("%H:%M:%S"),
            "label": label,
            "session_id": session_id[:8],
            "binding_accepted": verify_result["binding_accepted"],
            "detection_ran": verify_result["detection_ran"],
            "fused_score": verify_result.get("fused_score"),
            "accepted": verify_result["accepted"],
            "reason": verify_result["reason"],
            "total_ms": round(verify_result["timing_ms"].get("total_ms", verify_result["timing_ms"].get("binding_check_ms", 0.0)), 1),
        },
    )
    # The session nonce is single-use (spec Section 7) - force a fresh
    # session on the next capture/attack run.
    st.session_state.session = None
    return verify_result


def _render_result(verify_result: dict) -> None:
    if verify_result["accepted"]:
        st.success(f"ACCEPT - {verify_result['reason']}")
    elif verify_result["binding_accepted"]:
        st.error(f"REJECT (AI detection) - {verify_result['reason']}")
    else:
        st.error(f"REJECT (transaction binding) - {verify_result['reason']}")

    total_ms = verify_result["timing_ms"].get("total_ms", verify_result["timing_ms"].get("binding_check_ms", 0.0))
    cols = st.columns(3)
    cols[0].metric("Fused score", f"{verify_result['fused_score']:.2f}" if verify_result.get("fused_score") is not None else "n/a")
    cols[1].metric("Binding accepted", str(verify_result["binding_accepted"]))
    cols[2].metric("Total latency (ms)", f"{total_ms:.1f}")

    if verify_result.get("detection_scores"):
        st.subheader("Per-detector scores")
        st.bar_chart(verify_result["detection_scores"])
        mock_modules = [m for m, is_mock in (verify_result.get("detection_is_mock") or {}).items() if is_mock]
        if mock_modules:
            st.caption(f"Running in mock mode (no pretrained checkpoint loaded): {', '.join(mock_modules)}. See detection/README-models.md.")

    st.subheader("Latency breakdown (crypto/binding vs. detection vs. fusion)")
    st.json(verify_result["timing_ms"])

    with st.expander("Transaction-binding checks (Section 7)"):
        st.json(verify_result["binding_checks"])


def _live_capture_tab() -> None:
    st.write("Start a session, fulfil the liveness challenge on camera, then capture and verify a frame.")

    if st.button("Start new session", key="live_start"):
        _start_new_session()

    session = st.session_state.session
    if session:
        st.info(f"Session `{session['session_id'][:8]}` - challenge: **{session['challenge']}**")
    else:
        st.caption("No active session - click \"Start new session\" to get a nonce + liveness challenge.")

    try:
        from streamlit_webrtc import webrtc_streamer
    except ImportError:
        st.warning("streamlit-webrtc is not installed. Run `pip install -r requirements-client.txt` to enable live capture.")
        return

    def _on_frame(frame):
        st.session_state.captured_frame = frame.to_ndarray(format="rgb24")
        return frame

    webrtc_streamer(key="live-capture", video_frame_callback=_on_frame)

    challenge_response = st.text_input("What did you do/say to fulfil the challenge?", key="live_challenge_response")

    if st.button("Capture & Verify", disabled=session is None):
        frame = st.session_state.captured_frame
        if frame is None:
            st.warning("No frame captured yet - make sure the webcam stream above is running.")
            return
        try:
            result = _run_pipeline([frame], None, challenge_response, label="Live capture")
            _render_result(result)
        except ApiError as exc:
            st.error(str(exc))


def _simulate_attack_tab() -> None:
    st.write(
        "Loads a bundled demo-scale sample (see `demo_assets/README-assets.md`) and runs it through the "
        "identical crypto + binding + AI-detection pipeline as a live capture."
    )

    choice = st.selectbox("Attack type", list(ATTACK_FILES.keys()))
    uploaded = st.file_uploader("...or upload your own sample", type=["jpg", "jpeg", "png", "mp4", "mov"])
    challenge_response = st.text_input(
        "Challenge response (simulated - a real attacker may or may not know the current challenge)",
        value="done",
        key="attack_challenge_response",
    )

    if not st.button("Run simulated attack"):
        return

    if uploaded is not None:
        suffix = Path(uploaded.name).suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uploaded.getvalue())
            path = Path(tmp.name)
    else:
        path = ATTACKS_DIR / ATTACK_FILES[choice]

    if not path.exists():
        st.error(f"Sample file not found: `{path}`. See `demo_assets/README-assets.md` to add it.")
        return

    try:
        frames, frame_timestamps = load_attack_file(path)
        result = _run_pipeline(frames, frame_timestamps, challenge_response, label=choice)
        _render_result(result)
    except ApiError as exc:
        st.error(str(exc))
    except ValueError as exc:
        st.error(f"Could not load sample file: {exc}")


def main() -> None:
    _init_state()
    st.title("AI-Based Biometric Evidence Authentication - Live Demo")
    st.caption("Post-quantum channel (ML-KEM-768 / ML-DSA-65) + transaction binding + AI attack detection")
    _sidebar_health()

    tab_live, tab_attack = st.tabs(["Live Capture", "Simulate Attack"])
    with tab_live:
        _live_capture_tab()
    with tab_attack:
        _simulate_attack_tab()

    st.subheader("Recent verification attempts")
    if st.session_state.log:
        st.dataframe(st.session_state.log, use_container_width=True)
    else:
        st.caption("No attempts yet.")


if __name__ == "__main__":
    main()
