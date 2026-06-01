"""Corroboration rule tests.

Each finding class has a coded rule. These tests make the rules
machine-readable as well as human-readable.
"""

from __future__ import annotations

import pytest

from sworn.corroboration import gated_state, rule_for
from sworn.findings.schema import (
    EvidenceCitation,
    Finding,
    FindingClass,
    FindingState,
    Severity,
)
from sworn.gateway.provenance import new_invocation_id


def _finding(cls: FindingClass, families: list[str]) -> Finding:
    citations = []
    for i, fam in enumerate(families):
        citations.append(
            EvidenceCitation(
                invocation_id=new_invocation_id(),
                tool=f"t_{i}",
                artifact_family=fam,
                stdout_sha256="a" * 64,
            )
        )
    return Finding(
        case_id="C",
        host="H",
        finding_class=cls,
        severity=Severity.medium,
        title="placeholder",
        description="x" * 16,
        backing_invocations=citations,
    )


@pytest.mark.parametrize(
    "cls,families,expected",
    [
        (FindingClass.execution, ["prefetch"], FindingState.indication),
        (FindingClass.execution, ["prefetch", "amcache"], FindingState.draft),
        (FindingClass.execution, ["prefetch", "shimcache"], FindingState.draft),
        (FindingClass.persistence, ["run_key"], FindingState.indication),
        (FindingClass.persistence, ["run_key", "scheduled_task"], FindingState.draft),
        (FindingClass.lateral_movement, ["evtx_security_4624_logon"], FindingState.indication),
        (
            FindingClass.lateral_movement,
            ["evtx_security_4624_logon", "rdp_bitmap_cache"],
            FindingState.draft,
        ),
        (FindingClass.credential_access, ["lsass_dump", "mimikatz_yara"], FindingState.draft),
        (
            FindingClass.defense_evasion,
            ["evtx_security_1102_log_cleared"],
            FindingState.indication,
        ),
        (FindingClass.exfiltration, ["srum_network_bytes"], FindingState.indication),
    ],
)
def test_gated_state(cls: FindingClass, families: list[str], expected: FindingState) -> None:
    f = _finding(cls, families)
    assert gated_state(f) is expected


def test_unknown_family_does_not_satisfy_rule() -> None:
    f = _finding(FindingClass.execution, ["prefetch", "not_a_known_family"])
    assert gated_state(f) is FindingState.indication


def test_every_class_has_a_rule() -> None:
    # Make sure no finding class is silently uncorroborated.
    for cls in FindingClass:
        if rule_for(cls) is None:
            # acceptable for impact / discovery / collection / c2 if explicit
            assert cls in {
                FindingClass.discovery,
                FindingClass.collection,
                FindingClass.command_and_control,
                FindingClass.impact,
                FindingClass.privilege_escalation,
            }, f"class {cls!r} must have a corroboration rule"
