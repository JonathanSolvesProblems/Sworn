"""Ledger tests.

These tests are the evidence that moats #1 and #6 hold: tampered ledger lines
are detected, hash chaining is enforced, signatures actually verify.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sworn.gateway.ledger import (
    Ledger,
    LedgerVerifyError,
    load_or_create_signing_key,
)


@pytest.fixture()
def key_path(tmp_path: Path) -> Path:
    return tmp_path / "host.ed25519.pem"


@pytest.fixture()
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "actions.jsonl"


def test_append_and_verify_roundtrip(key_path: Path, ledger_path: Path) -> None:
    sk = load_or_create_signing_key(key_path)
    ledger = Ledger.open(ledger_path, sk)

    ledger.append("session_start", {"case_id": "T1"})
    ledger.append("tool_invocation", {"tool": "fls", "exit_code": 0})
    ledger.append("finding_submission", {"finding_id": "x" * 64, "state": "draft"})

    pk = sk.public_key()
    assert Ledger.verify(ledger_path, pk) == 3


def test_tampered_payload_fails_verify(key_path: Path, ledger_path: Path) -> None:
    sk = load_or_create_signing_key(key_path)
    ledger = Ledger.open(ledger_path, sk)
    ledger.append("session_start", {"case_id": "T1"})
    ledger.append("tool_invocation", {"tool": "fls", "exit_code": 0})

    lines = ledger_path.read_bytes().splitlines(keepends=True)
    obj = json.loads(lines[1])
    obj["payload"]["exit_code"] = 1  # tamper a single byte
    lines[1] = (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ledger_path.write_bytes(b"".join(lines))

    with pytest.raises(LedgerVerifyError):
        Ledger.verify(ledger_path, sk.public_key())


def test_reordered_lines_fail_verify(key_path: Path, ledger_path: Path) -> None:
    sk = load_or_create_signing_key(key_path)
    ledger = Ledger.open(ledger_path, sk)
    ledger.append("a", {"x": 1})
    ledger.append("b", {"x": 2})
    ledger.append("c", {"x": 3})

    lines = ledger_path.read_bytes().splitlines(keepends=True)
    swapped = [lines[0], lines[2], lines[1]]
    ledger_path.write_bytes(b"".join(swapped))

    with pytest.raises(LedgerVerifyError):
        Ledger.verify(ledger_path, sk.public_key())


def test_truncated_ledger_fails_verify(key_path: Path, ledger_path: Path) -> None:
    sk = load_or_create_signing_key(key_path)
    ledger = Ledger.open(ledger_path, sk)
    ledger.append("a", {"x": 1})

    raw = ledger_path.read_bytes()
    ledger_path.write_bytes(raw[: len(raw) // 2])  # cut a line in half

    with pytest.raises(LedgerVerifyError):
        Ledger.verify(ledger_path, sk.public_key())


def test_resuming_a_ledger_continues_chain(key_path: Path, ledger_path: Path) -> None:
    sk = load_or_create_signing_key(key_path)
    Ledger.open(ledger_path, sk).append("a", {"x": 1})
    Ledger.open(ledger_path, sk).append("b", {"x": 2})

    pk = sk.public_key()
    assert Ledger.verify(ledger_path, pk) == 2
