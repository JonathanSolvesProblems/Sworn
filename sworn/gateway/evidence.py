"""Evidence registry.

At session start every evidence file is hashed and registered. The gateway
re-verifies hashes on demand. Drift triggers EvidenceIntegrityViolation and
the gateway halts (fail-closed).
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path


class EvidenceIntegrityViolation(Exception):
    """Raised when an evidence file's SHA-256 changes during a session."""


@dataclass(frozen=True)
class RegisteredEvidence:
    evidence_id: str
    path: Path
    sha256: str
    size_bytes: int
    mtime_ns: int
    inode: int


def _hash_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


class EvidenceRegistry:
    """Tracks evidence files and their hashes for the lifetime of a session."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, RegisteredEvidence] = {}
        self._by_path: dict[str, str] = {}

    def register(self, path: Path) -> RegisteredEvidence:
        path = path.resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"evidence file not found: {path}")
        st = path.stat()
        sha = _hash_file(path)
        with self._lock:
            existing = self._by_path.get(str(path))
            if existing:
                return self._by_id[existing]
            ev = RegisteredEvidence(
                evidence_id=str(uuid.uuid4()),
                path=path,
                sha256=sha,
                size_bytes=st.st_size,
                mtime_ns=st.st_mtime_ns,
                inode=st.st_ino,
            )
            self._by_id[ev.evidence_id] = ev
            self._by_path[str(path)] = ev.evidence_id
            return ev

    def all(self) -> list[RegisteredEvidence]:
        with self._lock:
            return list(self._by_id.values())

    def get(self, evidence_id: str) -> RegisteredEvidence | None:
        with self._lock:
            return self._by_id.get(evidence_id)

    def get_by_path(self, path: Path) -> RegisteredEvidence | None:
        with self._lock:
            ev_id = self._by_path.get(str(path.resolve()))
            return self._by_id.get(ev_id) if ev_id else None

    def reverify(self, ev: RegisteredEvidence) -> None:
        """Recompute the hash and raise if it drifted."""
        current = _hash_file(ev.path)
        if current != ev.sha256:
            raise EvidenceIntegrityViolation(
                f"evidence {ev.evidence_id} ({ev.path}) hash changed: "
                f"{ev.sha256} -> {current}. Halting (fail-closed)."
            )

    def reverify_all(self) -> None:
        for ev in self.all():
            self.reverify(ev)


__all__ = ["EvidenceRegistry", "RegisteredEvidence", "EvidenceIntegrityViolation"]
