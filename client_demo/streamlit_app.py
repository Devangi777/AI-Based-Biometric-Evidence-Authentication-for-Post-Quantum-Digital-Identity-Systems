"""Streamlit demo client - spec Section 12.

Talks to the FastAPI server (server/main.py) at API_BASE_URL. Three tabs:
  - Live Capture: a real person on the laptop camera. The browser streams
    the camera over WebRTC (streamlit-webrtc) and a 4-second clip is
    recorded while the person performs the session's liveness challenge
    (client_demo/recorder.py). Expected outcome: ACCEPT. A two-photo
    fallback (st.camera_input) is available if WebRTC can't connect.
  - Simulate Attack: a pre-made sample from demo_assets/attacks/ (or an
    upload) through the identical pipeline. Expected outcome: REJECT, with
    the detector that caught it.
  - Tamper with Protocol: a genuine capture, but with the transaction
    binding or the sealed channel broken on purpose. Expected outcome:
    REJECT before any AI runs.

When liboqs is available on this machine the client encapsulates against the
session's ML-KEM public key itself and sends the evidence sealed with
AES-256-GCM (/verify-sealed); otherwise it falls back to plaintext /verify
and says so in the sidebar.
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import streamlit as st
from dotenv import load_dotenv
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # `streamlit run` doesn't add the repo root

from client_demo.api_client import (  # noqa: E402
    TAMPER_MODES,
    ApiError,
    can_seal,
    health,
    reset_replay_store,
    run_verification,
    session_start,
)
from client_demo.frame_utils import load_attack_file, quality_check  # noqa: E402
from client_demo.recorder import LOOK_STRAIGHT_SECONDS, RECORD_SECONDS, ClipRecorder, sample_frames  # noqa: E402

load_dotenv()

st.set_page_config(page_title="PQ Biometric Evidence Authentication", layout="wide")

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "demo_assets" / "attacks"
SAMPLES = {
    "Genuine sample (bona fide control)": "genuine_sample.jpg",
    "Replay (resubmitted genuine capture)": "replay_sample.jpg",
    "Presentation attack (printed photo)": "presentation_photo.jpg",
    "Presentation attack (screen replay)": "presentation_screen_replay.mp4",
    "Face morphing": "morphed_face.jpg",
    "Deepfake": "deepfake_sample.mp4",
    "Injection (virtual camera / screen recording)": "injection_sample.mp4",
}
MODULE_LABELS = {
    "presentation_attack": "Presentation attack (PAD)",
    "morph": "Face morph",
    "deepfake": "Deepfake",
    "replay": "Replay (pHash)",
    "injection": "Injection",
}
CHECK_LABELS = {
    "channel_authentic": "Sealed payload decrypts and authenticates (ML-KEM + AES-256-GCM)",
    "signature_valid": "ML-DSA-65 signature over hash ‖ nonce ‖ timestamp ‖ response",
    "nonce_unused": "Session nonce not used before",
    "timestamp_fresh": "Timestamp within the 30 s freshness window",
    "challenge_fulfilled": "Liveness challenge fulfilled",
    "evidence_matches_hash": "Submitted frames match the signed evidence hash",
}
MODULE_THRESHOLD = 0.5
FUSION_THRESHOLD = 0.6


def _init_state() -> None:
    st.session_state.setdefault("log", [])
    st.session_state.setdefault("live_session", None)
    st.session_state.setdefault("live_clip", None)


def _sidebar() -> None:
    st.sidebar.header("System status")
    try:
        info = health()
    except ApiError as exc:
        st.sidebar.error(f"Server unreachable: {exc}")
        st.sidebar.caption("Start it with `uvicorn server.main:app --port 8000` (see GUIDE.md).")
        return
    if info.get("liboqs_ready"):
        st.sidebar.success(f"Server online\n\n{info['kem_alg']} / {info['sig_alg']}")
    else:
        st.sidebar.warning(f"Server online, but liboqs not ready:\n\n{info.get('error', 'unknown error')}")

    if can_seal():
        st.sidebar.success("Client channel: sealed\n\nML-KEM-768 encapsulation + AES-256-GCM")
    else:
        st.sidebar.warning("Client channel: plaintext\n\nliboqs not installed on this client")

    st.sidebar.divider()
    st.sidebar.caption("Demo rehearsal (server needs DEMO_MODE=true)")
    if st.sidebar.button("Reset replay memory"):
        try:
            reset_replay_store()
            st.sidebar.info("Replay memory cleared - previously seen samples count as new again.")
        except ApiError:
            st.sidebar.error("Refused: start the server with DEMO_MODE=true in .env.")


def _record(label: str, result: dict) -> None:
    st.session_state.log.insert(
        0,
        {
            "time": time.strftime("%H:%M:%S"),
            "input": label,
            "decision": "ACCEPT" if result["accepted"] else "REJECT",
            "decided by": _decided_by(result),
            "fused score": None if result.get("fused_score") is None else round(result["fused_score"], 2),
            "channel": result.get("channel", "plaintext"),
            "server ms": round(result["timing_ms"].get("total_ms", 0.0), 1),
        },
    )


def _decided_by(result: dict) -> str:
    if result["accepted"]:
        return "all checks passed"
    failed = [k for k, ok in result["binding_checks"].items() if not ok]
    if failed:
        return "binding: " + ", ".join(failed)
    vetoed = result.get("below_threshold_modules") or []
    return "AI: " + (", ".join(MODULE_LABELS.get(m, m) for m in vetoed) if vetoed else "fused score below 0.6")


def _render_result(result: dict, session: dict) -> None:
    explanations = result.get("explanations") or []
    if result["accepted"]:
        st.success("### ✅ ACCEPT\n" + (explanations[0] if explanations else result["reason"]))
    else:
        stage = (
            "stopped by the cryptographic layer, before any AI ran"
            if not result["binding_accepted"]
            else "stopped by the AI evidence checks"
        )
        st.error(f"### ❌ REJECT — {stage}")
        st.markdown("**Why was this rejected?**")
        for line in explanations or [result["reason"]]:
            st.markdown(f"- {line}")

    col_crypto, col_binding, col_ai = st.columns([1, 1.3, 1.5])

    with col_crypto:
        st.markdown("**1 · Post-quantum channel**")
        st.write(f"Channel: `{result.get('channel', 'plaintext')}`")
        st.write(f"Session `{session['session_id'][:8]}`, challenge: *{session['challenge']}*")
        sealed = result.get("sealed_bytes")
        if sealed:
            st.write(f"ML-KEM ciphertext: {sealed['kem_ciphertext']} B")
            st.write(f"AES-GCM payload: {sealed['aes_gcm_ciphertext'] / 1024:.1f} kB")

    with col_binding:
        st.markdown("**2 · Transaction binding**")
        for check, ok in result["binding_checks"].items():
            st.write(("✅ " if ok else "❌ ") + CHECK_LABELS.get(check, check))

    with col_ai:
        st.markdown("**3 · AI evidence checks**")
        scores = result.get("detection_scores")
        if not scores:
            st.write("Not run — evidence was rejected earlier.")
        else:
            rows = [
                {
                    "detector": MODULE_LABELS.get(m, m),
                    "score": round(s, 2),
                    "verdict": "genuine" if s >= MODULE_THRESHOLD else "ATTACK",
                }
                for m, s in scores.items()
            ]
            st.dataframe(rows, hide_index=True, use_container_width=True)
            st.write(f"Fused score **{result['fused_score']:.2f}** (accept ≥ {FUSION_THRESHOLD}, and no detector < {MODULE_THRESHOLD})")
            mock = [MODULE_LABELS.get(m, m) for m, is_mock in (result.get("detection_is_mock") or {}).items() if is_mock]
            if mock:
                st.caption("Heuristic (no pretrained checkpoint): " + ", ".join(mock))

    timing = {k: round(v, 3) for k, v in result["timing_ms"].items()}
    st.caption("Server-side timing (ms): " + ", ".join(f"{k.replace('_ms', '')} {v}" for k, v in timing.items()))
    with st.expander("Raw server response"):
        st.json(result)


def _to_rgb(uploaded) -> np.ndarray:
    return np.array(Image.open(uploaded).convert("RGB"))


def _live_tab() -> None:
    st.markdown(
        "A real person in front of the laptop camera. **1.** Start a session to get a one-time code and a "
        "liveness challenge. **2.** Start the camera. **3.** Press **Record** and follow the prompts drawn on "
        f"the video: look straight at the camera, then perform the challenge ({RECORD_SECONDS:.0f} s). "
        "**4.** Verify."
    )
    if st.button("Start new session", type="primary"):
        st.session_state.live_session = session_start()
        st.session_state.live_clip = None

    session = st.session_state.live_session
    if session is None:
        st.info("No active session yet.")
        return

    challenge = session["challenge"]
    st.info(f"Session `{session['session_id'][:8]}` · nonce `{session['nonce'][:12]}…` · challenge: **{challenge}**")

    _record_clip(challenge)

    with st.expander("Camera stream won't connect? Use two photos instead"):
        _photo_fallback(session)

    clip = st.session_state.get("live_clip")
    if not clip:
        return
    frames, timestamps = clip
    st.markdown(f"**Recorded clip:** {len(timestamps)} frames over {timestamps[-1] - timestamps[0]:.1f} s; "
                f"{len(frames)} evenly spaced frames will be sent (the first one is the frontal frame).")
    st.image(frames, width=110, caption=[f"frame {i + 1}" for i in range(len(frames))])
    _verify_live(session, frames, timestamps, key="clip")


def _record_clip(challenge: str) -> None:
    try:
        import av
        from streamlit_webrtc import WebRtcMode, webrtc_streamer
    except ImportError:
        st.warning("streamlit-webrtc is not installed (`pip install -r requirements-client.txt`); "
                   "use the two-photo fallback below.")
        return

    recorder: ClipRecorder = st.session_state.setdefault("recorder", ClipRecorder())

    def on_frame(frame: "av.VideoFrame") -> "av.VideoFrame":
        # Runs in streamlit-webrtc's worker thread: touch only the recorder
        # object, never st.session_state.
        preview = recorder.on_frame(frame.to_ndarray(format="rgb24"), time.time())
        return av.VideoFrame.from_ndarray(preview, format="rgb24")

    try:
        ctx = webrtc_streamer(
            key="live-camera",
            mode=WebRtcMode.SENDRECV,
            video_frame_callback=on_frame,
            media_stream_constraints={"video": {"width": {"ideal": 640}, "height": {"ideal": 480}}, "audio": False},
            async_processing=True,
        )
    except Exception as exc:  # the component needs a live Streamlit server + browser
        st.warning(f"Live video is unavailable here ({exc}). Use the two-photo method below.")
        return
    if not ctx.state.playing:
        st.caption("Press **START** above and allow camera access; the Record button appears once the video is live.")
        return

    if st.button(f"⏺ Record {RECORD_SECONDS:.0f} s clip", type="primary"):
        recorder.start(challenge)
        status = st.empty()
        progress = st.progress(0.0)
        t0 = time.time()
        while (elapsed := time.time() - t0) < RECORD_SECONDS + 0.2:
            phase = "Look straight at the camera" if elapsed < LOOK_STRAIGHT_SECONDS else f"Now: **{challenge}**"
            status.markdown(f"🔴 Recording… {phase}")
            progress.progress(min(elapsed / RECORD_SECONDS, 1.0))
            time.sleep(0.1)
        status.empty()
        progress.empty()
        frames, timestamps = recorder.take()
        if len(frames) < 10:
            st.error(f"Only {len(frames)} frames arrived while recording. Check that the video above is moving, then record again.")
            return
        st.session_state.live_clip = (sample_frames(frames), timestamps)


def _photo_fallback(session: dict) -> None:
    challenge = session["challenge"]
    movement = "number" not in challenge.lower()
    first = st.camera_input("Photo 1 — look straight at the camera", key=f"cam1-{session['session_id']}")
    second = st.camera_input(f"Photo 2 — now: {challenge.lower()}", key=f"cam2-{session['session_id']}") if movement else None
    if first is None or (movement and second is None):
        return
    frames = [_to_rgb(first)] + ([_to_rgb(second)] if second is not None else [])
    _verify_live(session, frames, None, key="photos")


def _verify_live(session: dict, frames: list, timestamps: list[float] | None, key: str) -> None:
    challenge = session["challenge"]
    if "number" in challenge.lower():
        response = st.text_input("Type the number you said", key=f"resp-{key}-{session['session_id']}")
    else:
        response = "performed: " + challenge.lower()

    ok, message = quality_check(frames[0])
    if not ok:
        st.warning(f"Local quality check: {message}. Record again, or submit anyway to see the server's verdict.")
    submit_anyway = (not ok) and st.checkbox("Submit anyway", key=f"anyway-{key}")
    if st.button("Verify", type="primary", key=f"verify-{key}", disabled=not ok and not submit_anyway):
        try:
            _, result = run_verification(frames, timestamps, response, session=session)
        except ApiError as exc:
            st.error(str(exc))
            return
        st.session_state.live_session = None  # nonce is single-use
        st.session_state.live_clip = None
        _record("Live capture", result)
        _render_result(result, session)


def _attack_tab() -> None:
    st.markdown(
        "A pre-made sample (generated by `scripts/make_demo_assets.py`) sent through the **same** channel, "
        "binding and detection pipeline as a live capture. The attacker is assumed to know the live challenge, "
        "so the binding passes and it is the AI layer that must catch it."
    )
    choice = st.selectbox("Sample", list(SAMPLES))
    uploaded = st.file_uploader("…or upload your own image/video", type=["jpg", "jpeg", "png", "mp4", "mov"])

    if not st.button("Submit sample", type="primary"):
        return
    if uploaded is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded.name).suffix) as tmp:
            tmp.write(uploaded.getvalue())
        path, label = Path(tmp.name), f"Upload: {uploaded.name}"
    else:
        path, label = ATTACKS_DIR / SAMPLES[choice], choice
    if not path.exists():
        st.error(f"`{path.name}` not found. Run `python scripts/make_demo_assets.py` first.")
        return

    try:
        frames, frame_timestamps = load_attack_file(path)
        session, result = run_verification(frames, frame_timestamps)
    except (ApiError, ValueError) as exc:
        st.error(str(exc))
        return
    _record(label, result)
    if len(frames) > 1:
        st.caption(f"Video: {len(frames)} frames sampled.")
    st.image(frames[0], caption=label, width=240)
    _render_result(result, session)


def _tamper_tab() -> None:
    st.markdown(
        "The **genuine** sample, but with the protocol attacked. These are rejected by cryptography and session "
        "binding alone, in about a millisecond, without running any detector."
    )
    mode = st.radio("Attack on the protocol", list(TAMPER_MODES), format_func=TAMPER_MODES.get)
    if not st.button("Run tampered submission", type="primary"):
        return
    if mode == "corrupt_channel" and not can_seal():
        st.error("Needs the sealed channel (liboqs on this client).")
        return
    path = ATTACKS_DIR / SAMPLES["Genuine sample (bona fide control)"]
    if not path.exists():
        st.error("`genuine_sample.jpg` not found. Run `python scripts/make_demo_assets.py` first.")
        return
    try:
        frames, _ = load_attack_file(path)
        session, result = run_verification(frames, tamper=mode)
    except ApiError as exc:
        st.error(str(exc))
        return
    _record(f"Tamper: {mode}", result)
    _render_result(result, session)


def main() -> None:
    _init_state()
    st.title("AI-Based Biometric Evidence Authentication")
    st.caption("Post-quantum channel (ML-KEM-768 / ML-DSA-65) · transaction binding · AI attack detection")
    _sidebar()

    tab_live, tab_attack, tab_tamper = st.tabs(["Live Capture", "Simulate Attack", "Tamper with Protocol"])
    with tab_live:
        _live_tab()
    with tab_attack:
        _attack_tab()
    with tab_tamper:
        _tamper_tab()

    st.divider()
    st.subheader("Verification log")
    if st.session_state.log:
        st.dataframe(st.session_state.log, hide_index=True, use_container_width=True)
    else:
        st.caption("No attempts yet.")


if __name__ == "__main__":
    main()
