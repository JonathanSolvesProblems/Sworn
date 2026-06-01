"""Finding schema invariants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sworn.findings.schema import (
    EvidenceCitation,
    Finding,
    FindingClass,
    FindingState,
    Severity,
)
from sworn.gateway.provenance import new_invocation_id


def _citation(family: str = "prefetch") -> EvidenceCitation:
    return EvidenceCitation(
        invocation_id=new_invocation_id(),
        tool="prefetch_pecmd",
        artifact_family=family,
        stdout_sha256="a" * 64,
    )


def test_finding_id_is_deterministic() -> None:
    cit = _citation()
    a = Finding(
        case_id="C",
        host="H",
        finding_class=FindingClass.execution,
        severity=Severity.high,
        title="title-string-x",
        description="desc-string",
        backing_invocations=[cit],
    )
    b = Finding(
        case_id="C",
        host="H",
        finding_class=FindingClass.execution,
        severity=Severity.high,
        title="title-string-x",
        description="desc-string",
        backing_invocations=[cit],
    )
    assert a.finding_id == b.finding_id


def test_finding_id_changes_with_citations() -> None:
    a = Finding(
        case_id="C",
        host="H",
        finding_class=FindingClass.execution,
        severity=Severity.high,
        title="t-string",
        description="d-string",
        backing_invocations=[_citation()],
    )
    b = Finding(
        case_id="C",
        host="H",
        finding_class=FindingClass.execution,
        severity=Severity.high,
        title="t-string",
        description="d-string",
        backing_invocations=[_citation()],
    )
    assert a.finding_id != b.finding_id


def test_no_citations_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            case_id="C",
            host="H",
            finding_class=FindingClass.execution,
            severity=Severity.high,
            title="t-string",
            description="d-string",
            backing_invocations=[],
        )


def test_approved_state_requires_signature() -> None:
    with pytest.raises(ValidationError):
        Finding(
            case_id="C",
            host="H",
            finding_class=FindingClass.execution,
            severity=Severity.high,
            title="t-string",
            description="d-string",
            backing_invocations=[_citation()],
            state=FindingState.approved,
        )


def test_approved_state_with_signature_ok() -> None:
    f = Finding(
        case_id="C",
        host="H",
        finding_class=FindingClass.execution,
        severity=Severity.high,
        title="t-string",
        description="d-string",
        backing_invocations=[_citation()],
        state=FindingState.approved,
        approved_by="examiner@example.org",
        approval_hmac="deadbeef",
    )
    assert f.state is FindingState.approved


def test_invalid_mitre_technique_format_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            case_id="C",
            host="H",
            finding_class=FindingClass.execution,
            severity=Severity.high,
            title="t-string",
            description="d-string",
            backing_invocations=[_citation()],
            mitre_techniques=["mimikatz"],  # not Txxxx
        )


def test_rejected_state_requires_reason() -> None:
    with pytest.raises(ValidationError):
        Finding(
            case_id="C",
            host="H",
            finding_class=FindingClass.execution,
            severity=Severity.high,
            title="t-string",
            description="d-string",
            backing_invocations=[_citation()],
            state=FindingState.rejected,
        )
