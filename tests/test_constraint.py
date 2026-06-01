"""Inference Constraint Gateway tests.

These tests are the evidence that moats #1 (provenance) and #3 (cross-tool
corroboration) hold by architecture, not by prompt.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sworn.findings.schema import (
    EvidenceCitation,
    Finding,
    FindingClass,
    FindingState,
    Severity,
)
from sworn.gateway.constraint import FindingRejected
from sworn.gateway.session import Session
from sworn.gateway.provenance import Invocation, new_invocation_id


def _make_session(tmp_path: Path) -> Session:
    return Session.start(
        case_id="TEST-001",
        case_root=tmp_path / "cases" / "TEST-001",
        signing_key_path=tmp_path / "host.ed25519.pem",
    )


def _record_invocation(
    session: Session, *, tool: str, stdout_sha256: str = "a" * 64
) -> Invocation:
    inv = Invocation(
        invocation_id=new_invocation_id(),
        seq=session.invocations.next_seq(),
        case_id=session.case_id,
        tool=tool,
        args=("--demo",),
        stdout_sha256=stdout_sha256,
        stderr_sha256="0" * 64,
        exit_code=0,
        latency_ms=1,
        started_at=Invocation.now(),
        finished_at=Invocation.now(),
    )
    session.invocations.record(inv)
    return inv


def _finding(
    session: Session,
    *,
    finding_class: FindingClass,
    citations: list[EvidenceCitation],
) -> Finding:
    return Finding(
        case_id=session.case_id,
        host="DESKTOP-TEST",
        finding_class=finding_class,
        severity=Severity.high,
        title="Test finding for unit test",
        description="Synthesized in a unit test to exercise the gateway.",
        backing_invocations=citations,
        confidence=0.9,
    )


def test_finding_without_backing_is_invalid(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    with pytest.raises(Exception):
        Finding(
            case_id=session.case_id,
            host="x",
            finding_class=FindingClass.execution,
            severity=Severity.medium,
            title="bare claim",
            description="no provenance",
            backing_invocations=[],
        )


def test_unknown_invocation_id_rejected(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    bogus = EvidenceCitation(
        invocation_id=new_invocation_id(),
        tool="memory_volatility_run",
        artifact_family="volatility_memory",
        stdout_sha256="b" * 64,
    )
    f = _finding(session, finding_class=FindingClass.execution, citations=[bogus])
    with pytest.raises(FindingRejected) as e:
        session.gateway.submit(f)
    assert e.value.reason is FindingRejected.Reason.unknown_invocation


def test_stdout_hash_mismatch_rejected(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    inv = _record_invocation(session, tool="prefetch_pecmd", stdout_sha256="a" * 64)
    bad_citation = EvidenceCitation(
        invocation_id=inv.invocation_id,
        tool="prefetch_pecmd",
        artifact_family="prefetch",
        stdout_sha256="c" * 64,  # wrong hash
    )
    f = _finding(session, finding_class=FindingClass.execution, citations=[bad_citation])
    with pytest.raises(FindingRejected) as e:
        session.gateway.submit(f)
    assert e.value.reason is FindingRejected.Reason.stdout_hash_mismatch


def test_single_source_execution_downgrades_to_indication(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    inv = _record_invocation(session, tool="prefetch_pecmd")
    citation = EvidenceCitation(
        invocation_id=inv.invocation_id,
        tool="prefetch_pecmd",
        artifact_family="prefetch",
        stdout_sha256=inv.stdout_sha256,
    )
    f = _finding(session, finding_class=FindingClass.execution, citations=[citation])
    result = session.gateway.submit(f)
    assert result.state is FindingState.indication


def test_two_family_execution_reaches_draft(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    inv_pf = _record_invocation(session, tool="prefetch_pecmd")
    inv_rip = _record_invocation(session, tool="registry_regripper", stdout_sha256="d" * 64)
    citations = [
        EvidenceCitation(
            invocation_id=inv_pf.invocation_id,
            tool="prefetch_pecmd",
            artifact_family="prefetch",
            stdout_sha256=inv_pf.stdout_sha256,
        ),
        EvidenceCitation(
            invocation_id=inv_rip.invocation_id,
            tool="registry_regripper",
            artifact_family="amcache",
            stdout_sha256=inv_rip.stdout_sha256,
        ),
    ]
    f = _finding(session, finding_class=FindingClass.execution, citations=citations)
    result = session.gateway.submit(f)
    assert result.state is FindingState.draft


def test_case_id_mismatch_rejected(tmp_path: Path) -> None:
    session = _make_session(tmp_path)
    inv = _record_invocation(session, tool="prefetch_pecmd")
    citation = EvidenceCitation(
        invocation_id=inv.invocation_id,
        tool="prefetch_pecmd",
        artifact_family="prefetch",
        stdout_sha256=inv.stdout_sha256,
    )
    f = Finding(
        case_id="WRONG-CASE",
        host="x",
        finding_class=FindingClass.execution,
        severity=Severity.medium,
        title="mismatched case",
        description="should be rejected",
        backing_invocations=[citation],
    )
    with pytest.raises(FindingRejected):
        session.gateway.submit(f)


def test_two_invocations_same_family_still_demotes(tmp_path: Path) -> None:
    """Two prefetch hits is still ONE artifact family. Must demote."""
    session = _make_session(tmp_path)
    inv1 = _record_invocation(session, tool="prefetch_pecmd", stdout_sha256="e" * 64)
    inv2 = _record_invocation(session, tool="prefetch_pecmd", stdout_sha256="f" * 64)
    citations = [
        EvidenceCitation(
            invocation_id=inv1.invocation_id,
            tool="prefetch_pecmd",
            artifact_family="prefetch",
            stdout_sha256=inv1.stdout_sha256,
        ),
        EvidenceCitation(
            invocation_id=inv2.invocation_id,
            tool="prefetch_pecmd",
            artifact_family="prefetch",
            stdout_sha256=inv2.stdout_sha256,
        ),
    ]
    f = _finding(session, finding_class=FindingClass.execution, citations=citations)
    result = session.gateway.submit(f)
    assert result.state is FindingState.indication
