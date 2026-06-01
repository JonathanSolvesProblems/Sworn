"""Append-only Ed25519-signed JSONL ledger.

Every meaningful state change in a SWORN session is appended to a single JSONL
file. Each line is hash-chained to the previous and signed with the session
Ed25519 key. Tampering with any line invalidates the chain from that point
forward, which `sworn verify ledger` detects.

Why this design over a database:
  - JSONL is human-inspectable, which matters for court-defensibility.
  - Append-only with chained hashes is what 800-86 §3.1 implicitly demands.
  - No external dependency at runtime; only `cryptography` for signing.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

GENESIS_HASH = "0" * 64


class LedgerVerifyError(Exception):
    """Raised when ledger verification detects tampering."""


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    ts: str
    prev_sha256: str
    kind: str
    payload: dict[str, Any]
    signature_hex: str

    def to_jsonl(self) -> str:
        return (
            json.dumps(
                {
                    "seq": self.seq,
                    "ts": self.ts,
                    "prev_sha256": self.prev_sha256,
                    "kind": self.kind,
                    "payload": self.payload,
                    "signature_hex": self.signature_hex,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

    def signing_bytes(self) -> bytes:
        return json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "prev_sha256": self.prev_sha256,
                "kind": self.kind,
                "payload": self.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def _hash_line(line_bytes: bytes) -> str:
    return hashlib.sha256(line_bytes).hexdigest()


class Ledger:
    """Append-only signed JSONL.

    Usage:
        ledger = Ledger.open(path, signing_key)
        ledger.append("invocation", {...})
        Ledger.verify(path, public_key)
    """

    def __init__(
        self,
        path: Path,
        signing_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        seq: int,
        prev_sha256: str,
    ) -> None:
        self._path = path
        self._signing_key = signing_key
        self._public_key = public_key
        self._seq = seq
        self._prev_sha256 = prev_sha256
        self._lock = threading.Lock()

    @classmethod
    def open(cls, path: Path, signing_key: Ed25519PrivateKey) -> Ledger:
        path.parent.mkdir(parents=True, exist_ok=True)
        public_key = signing_key.public_key()
        seq = 0
        prev_sha256 = GENESIS_HASH
        if path.exists():
            with path.open("rb") as f:
                for line in f:
                    seq += 1
                    prev_sha256 = _hash_line(line)
        return cls(path, signing_key, public_key, seq, prev_sha256)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        with self._lock:
            next_seq = self._seq + 1
            entry = LedgerEntry(
                seq=next_seq,
                ts=datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                prev_sha256=self._prev_sha256,
                kind=kind,
                payload=payload,
                signature_hex="",
            )
            sig = self._signing_key.sign(entry.signing_bytes()).hex()
            signed = LedgerEntry(
                seq=entry.seq,
                ts=entry.ts,
                prev_sha256=entry.prev_sha256,
                kind=entry.kind,
                payload=entry.payload,
                signature_hex=sig,
            )
            line = signed.to_jsonl().encode("utf-8")
            # write + fsync to make tamper-after-crash visible on verify
            with self._path.open("ab") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            self._seq = next_seq
            self._prev_sha256 = _hash_line(line)
            return signed

    @staticmethod
    def verify(path: Path, public_key: Ed25519PublicKey) -> int:
        """Re-walk the chain. Returns the number of verified entries.

        Raises LedgerVerifyError on the first inconsistency.
        """
        expected_prev = GENESIS_HASH
        expected_seq = 0
        verified = 0
        if not path.exists():
            return 0
        with path.open("rb") as f:
            for raw in f:
                expected_seq += 1
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise LedgerVerifyError(
                        f"line {expected_seq}: invalid JSON: {e}"
                    ) from e
                if data.get("seq") != expected_seq:
                    raise LedgerVerifyError(
                        f"line {expected_seq}: seq mismatch "
                        f"(got {data.get('seq')!r})"
                    )
                if data.get("prev_sha256") != expected_prev:
                    raise LedgerVerifyError(
                        f"line {expected_seq}: prev_sha256 mismatch"
                    )
                sig_hex = data.get("signature_hex", "")
                if not isinstance(sig_hex, str) or not sig_hex:
                    raise LedgerVerifyError(f"line {expected_seq}: missing signature")
                signing_bytes = json.dumps(
                    {
                        "seq": data["seq"],
                        "ts": data["ts"],
                        "prev_sha256": data["prev_sha256"],
                        "kind": data["kind"],
                        "payload": data["payload"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                try:
                    public_key.verify(bytes.fromhex(sig_hex), signing_bytes)
                except (InvalidSignature, ValueError) as e:
                    raise LedgerVerifyError(
                        f"line {expected_seq}: signature invalid"
                    ) from e
                expected_prev = _hash_line(raw)
                verified += 1
        return verified


def load_or_create_signing_key(key_path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from disk or create one with 0600 perms.

    The key lives outside the evidence directory by convention. `install.sh`
    creates it under `~/.sworn/keys/`.
    """
    if key_path.exists():
        return load_pem_private_key(key_path.read_bytes(), password=None)  # type: ignore[return-value]
    key_path.parent.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_path.write_bytes(pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        # Windows host running dev tests; the SIFT VM will enforce mode.
        pass
    return sk


def export_public_key_pem(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


__all__ = [
    "Ledger",
    "LedgerEntry",
    "LedgerVerifyError",
    "load_or_create_signing_key",
    "export_public_key_pem",
    "GENESIS_HASH",
]
