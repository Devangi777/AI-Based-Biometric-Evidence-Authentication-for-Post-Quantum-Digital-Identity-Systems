"""Transaction-binding / freshness mechanism - spec Section 7.

This is the integration point between the crypto layer (Section 5) and the
AI detection pipeline (Section 6): it's what prevents replay of even a
*genuine* previously-captured biometric sample, by making each session's
required evidence unique (a fresh nonce + a fresh liveness challenge).

Section 7 step 6 requires four checks before evidence proceeds to AI
detection:
  (a) ML-DSA signature validity
  (b) session_nonce matches the one issued, and hasn't been used before
  (c) timestamp is within an acceptable freshness window
  (d) the liveness challenge was correctly fulfilled

(a)-(c) are self-contained cryptographic/bookkeeping checks and are fully
implemented here. (d) is explicitly scoped by the spec as "checked by the AI
pipeline (e.g. did the head actually turn left in the frames)" - i.e. it
depends on detection modules that don't exist yet at this stage of the
build. `check_transaction_binding` takes a `challenge_check` callable so
detection/fusion.py can supply the real implementation once it exists,
without this module needing to change; until then it defaults to
`placeholder_challenge_check`, which only checks that some non-empty
response was submitted (NOT a real liveness verdict) and is clearly labeled
as such everywhere it's used.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from crypto.signature import build_binding_payload, verify as sig_verify

DEFAULT_FRESHNESS_WINDOW_SECONDS = 30

ChallengeCheck = Callable[[str, str], bool]


@dataclass
class BindingCheckResult:
    accepted: bool
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def _fail(self, check_name: str, ok: bool, reason: str) -> None:
        self.checks[check_name] = ok
        if not ok:
            self.accepted = False
            self.reasons.append(reason)


def placeholder_challenge_check(challenge: str, challenge_response: str) -> bool:
    """Stand-in for AI-verified challenge fulfilment (Section 7 step 6d).

    Only checks that *some* response was actually submitted - this is a
    bookkeeping placeholder, not a liveness check. Replace by passing a real
    `challenge_check` (e.g. from detection/fusion.py, once it exists) into
    `check_transaction_binding`.
    """
    return bool(challenge_response and challenge_response.strip())


def parse_timestamp(timestamp: str) -> datetime:
    """Parse an ISO-8601 timestamp (accepting a trailing 'Z') into an
    aware UTC datetime. Raises ValueError on anything else."""
    normalized = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def check_transaction_binding(
    *,
    session_nonce: bytes,
    session_challenge: str,
    client_public_key: bytes,
    sig_alg: str,
    evidence_hash: bytes,
    timestamp: str,
    challenge_response: str,
    signature: bytes,
    nonce_already_used: bool,
    freshness_window_seconds: int = DEFAULT_FRESHNESS_WINDOW_SECONDS,
    now: datetime | None = None,
    challenge_check: ChallengeCheck = placeholder_challenge_check,
) -> BindingCheckResult:
    """Run all four Section 7 step-6 checks and return a combined verdict.

    The payload is always rebuilt server-side from `session_nonce` (the
    value the server itself issued and stored) rather than trusting any
    nonce the caller might send - this is what makes check (b)'s "matches
    the one it issued" half structural rather than a comparison that could
    be spoofed. Only "hasn't been used before" (`nonce_already_used`) is a
    real runtime decision, and that's the caller's (server/main.py's)
    responsibility to track per session.
    """
    result = BindingCheckResult(accepted=True)
    now = now or datetime.now(timezone.utc)

    # (a) ML-DSA signature validity
    payload = build_binding_payload(evidence_hash, session_nonce, timestamp, challenge_response)
    try:
        sig_ok = sig_verify(payload, signature, client_public_key, alg=sig_alg)
    except Exception:
        sig_ok = False
    result._fail("signature_valid", sig_ok, "ML-DSA signature verification failed")

    # (b) nonce single-use
    result._fail(
        "nonce_unused",
        not nonce_already_used,
        "session nonce has already been used for a prior submission (possible replay)",
    )

    # (c) timestamp freshness
    try:
        ts = parse_timestamp(timestamp)
        delta_seconds = abs((now - ts).total_seconds())
        fresh = delta_seconds <= freshness_window_seconds
        reason = f"timestamp is {delta_seconds:.1f}s old, outside the {freshness_window_seconds}s freshness window"
    except (ValueError, TypeError):
        fresh = False
        reason = "timestamp could not be parsed as ISO-8601"
    result._fail("timestamp_fresh", fresh, reason)

    # (d) challenge fulfilment - see module docstring re: AI-pipeline hook
    challenge_ok = challenge_check(session_challenge, challenge_response)
    result._fail("challenge_fulfilled", challenge_ok, "liveness challenge was not fulfilled")

    return result
