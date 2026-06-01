"""TheHive write-back tests (offline / dry-run only)."""

from __future__ import annotations

import hmac
from hashlib import sha256

import pytest

from sworn.findings.schema import (
    EvidenceCitation,
    Finding,
    FindingClass,
    FindingState,
    Severity,
)
from sworn.gateway.provenance import new_invocation_id
from sworn.writeback import (
    TheHiveConfig,
    TheHiveWriteback,
    WritebackBlocked,
)


def _citation() -> EvidenceCitation:
    return EvidenceCitation(
        invocation_id=new_invocation_id(),
        tool="prefetch_pecmd",
        artifact_family="prefetch",
        stdout_sha256="a" * 64,
    )


def _draft_finding() -> Finding:
    return Finding(
        case_id="C",
        host="H",
        finding_class=FindingClass.execution,
        severity=Severity.high,
        title="test-execution-finding",
        description="x" * 32,
        backing_invocations=[_citation()],
        state=FindingState.draft,
    )


def _approved_finding(*, examiner: str, passphrase: bytes) -> Finding:
    f = _draft_finding()
    msg = f"{f.finding_id}|{examiner}".encode("utf-8")
    mac = hmac.new(sha256(passphrase).digest(), msg, sha256).hexdigest()
    return f.model_copy(
        update={
            "state": FindingState.approved,
            "approved_by": examiner,
            "approval_hmac": mac,
        }
    )


def test_draft_finding_blocked() -> None:
    wb = TheHiveWriteback(TheHiveConfig(base_url="https://thehive.example"))
    with pytest.raises(WritebackBlocked):
        wb.push(_draft_finding(), dry_run=True)


def test_approved_finding_dry_run_payload() -> None:
    passphrase = b"super-secret"
    f = _approved_finding(examiner="examiner@example.org", passphrase=passphrase)
    wb = TheHiveWriteback(
        TheHiveConfig(base_url="https://thehive.example"),
        approval_passphrase=passphrase,
    )
    result = wb.push(f, dry_run=True)
    assert result.dry_run is True
    assert result.payload["title"].startswith("SWORN: ")
    assert any(t.startswith("class:") for t in result.payload["tags"])
    assert result.payload["customFields"]["swornFindingId"]["string"] == f.finding_id


def test_bad_passphrase_blocks() -> None:
    f = _approved_finding(examiner="examiner@example.org", passphrase=b"right")
    wb = TheHiveWriteback(
        TheHiveConfig(base_url="https://thehive.example"),
        approval_passphrase=b"wrong",
    )
    with pytest.raises(WritebackBlocked):
        wb.push(f, dry_run=True)
