"""Tool-invocation provenance.

An Invocation is the record of a single typed tool call: which tool, what
arguments, what stdout/stderr (hashed), what exit code. The gateway stamps
every Invocation with a fresh UUIDv4 server-side. The LLM never authors an
invocation_id; it can only cite one it was already handed.

That property is what makes Finding.backing_invocations un-spoofable.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_invocation_id() -> str:
    return str(uuid.uuid4())


@dataclass(frozen=True)
class Invocation:
    invocation_id: str
    seq: int
    case_id: str
    tool: str
    args: tuple[str, ...]
    stdout_sha256: str
    stderr_sha256: str
    exit_code: int
    latency_ms: int
    started_at: datetime
    finished_at: datetime
    evidence_ids_read: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids_written: tuple[str, ...] = field(default_factory=tuple)
    # Set by LLM-driven orchestrators when the invocation is attributable to a
    # specific LLM turn. Tool subprocesses themselves consume no LLM tokens;
    # this field is for ledger-level audit of total tokens spent on the case.
    tokens_estimated: int | None = None

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)


class InvocationStore:
    """Thread-safe in-memory store of every Invocation produced this session.

    The gateway looks up cited invocation_ids here when validating a finding.
    The store is monotonic-only (no deletes, no rewrites); replay of the
    ledger reconstructs it bit-for-bit.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, Invocation] = {}
        self._seq = 0

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def record(self, inv: Invocation) -> None:
        with self._lock:
            if inv.invocation_id in self._by_id:
                raise RuntimeError(
                    f"invocation_id collision: {inv.invocation_id}. "
                    "This indicates a bug or tampering."
                )
            self._by_id[inv.invocation_id] = inv

    def get(self, invocation_id: str) -> Invocation | None:
        with self._lock:
            return self._by_id.get(invocation_id)

    def __contains__(self, invocation_id: str) -> bool:
        with self._lock:
            return invocation_id in self._by_id

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)


__all__ = ["Invocation", "InvocationStore", "new_invocation_id", "sha256_bytes"]
