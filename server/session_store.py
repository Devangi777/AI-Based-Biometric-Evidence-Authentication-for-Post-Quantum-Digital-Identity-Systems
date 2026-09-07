"""In-memory session state.

A prototype-scale store (dict keyed by session_id) is sufficient for a
single-process demo server; a production system would back this with Redis
or similar so nonce single-use is enforced across replicas. Holds the native
oqs keypair objects for the lifetime of the session, so sessions must be
closed to free them.
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field

from crypto.kem import ServerKemSession
from crypto.signature import SignerIdentity
from server.config import settings

CHALLENGE_PROMPTS = [
    "Turn your head slightly left",
    "Turn your head slightly right",
    "Nod your head once",
    "Say the number {digits}",
]


def _generate_challenge() -> str:
    prompt = secrets.choice(CHALLENGE_PROMPTS)
    if "{digits}" in prompt:
        digits = "".join(secrets.choice("0123456789") for _ in range(4))
        prompt = prompt.format(digits=digits)
    return prompt


@dataclass
class Session:
    session_id: str
    nonce: bytes
    challenge: str
    created_at: float
    kem: ServerKemSession
    client_signer: SignerIdentity
    nonce_used: bool = False
    kem_established: bool = False
    used_evidence_hashes: set = field(default_factory=set)

    def is_fresh(self, timestamp: float, window_seconds: int | None = None) -> bool:
        window = settings.freshness_window_seconds if window_seconds is None else window_seconds
        return abs(time.time() - timestamp) <= window

    def close(self) -> None:
        self.kem.close()
        self.client_signer.close()


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self) -> Session:
        session_id = str(uuid.uuid4())
        nonce = os.urandom(settings.nonce_bytes)
        challenge = _generate_challenge()

        kem = ServerKemSession(alg=settings.kem_alg)
        kem.generate_keypair()

        client_signer = SignerIdentity(alg=settings.sig_alg)

        session = Session(
            session_id=session_id,
            nonce=nonce,
            challenge=challenge,
            created_at=time.time(),
            kem=kem,
            client_signer=client_signer,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def delete(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is not None:
            session.close()

    def all_active(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())


def nonce_b64(nonce: bytes) -> str:
    return base64.b64encode(nonce).decode("ascii")


# Process-wide singleton, matching FastAPI's typical app-state pattern for a
# small prototype server.
store = SessionStore()
