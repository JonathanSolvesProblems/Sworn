"""Defensive degrade: missing tool binary must not crash the orchestrator.

The TypedTool base class emits a tombstone Invocation with exit_code=-127
when its binary is not on PATH. SpecialistLoop sees the -127 and skips
retries, logging a graceful give-up. This keeps the audit trail honest
without crashing the run if a SIFT VM is missing one tool.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sworn.agents.loop import SpecialistLoop
from sworn.gateway.session import Session
from sworn.tools._base import ToolArgs, TypedTool


class _AbsentArgs(ToolArgs):
    pass


class _AbsentTool(TypedTool):
    name = "_absent_tool_for_tests"
    description = "A tool whose binary does not exist."
    binary = "definitely-not-a-real-binary-xyzzy-12345"
    artifact_family = "test"
    Args = _AbsentArgs

    def build_argv(self, args):  # type: ignore[override]
        return ["--demo"]


def _session(tmp_path: Path) -> Session:
    return Session.start(
        case_id="UNAVAIL-001",
        case_root=tmp_path / "cases" / "UNAVAIL-001",
        signing_key_path=tmp_path / "host.ed25519.pem",
    )


@pytest.mark.asyncio
async def test_missing_binary_returns_tombstone_not_exception(tmp_path: Path) -> None:
    session = _session(tmp_path)
    tool = _AbsentTool(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )
    result = await tool.execute(_AbsentArgs())
    assert result.invocation.exit_code == -127
    assert result.invocation.tool == "_absent_tool_for_tests"
    assert "not found" in result.stdout_for_llm.lower()


@pytest.mark.asyncio
async def test_specialist_loop_gives_up_on_missing_binary_without_retry(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path)
    loop = SpecialistLoop(name="test", session=session, max_iterations=10)
    tool = _AbsentTool(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )
    result = await loop.run_tool(
        tool,
        _AbsentArgs(),
        artifact_family="test",
        summary_template="test: {tool} -> {invocation_id}",
        max_retries=2,
    )
    assert result.invocation.exit_code == -127
    # No replan attempts because the binary is missing
    assert len(loop.replans) == 0
    # Only one iteration consumed (no retries)
    assert loop.iteration == 1


@pytest.mark.asyncio
async def test_tool_unavailable_emits_ledger_entries(tmp_path: Path) -> None:
    session = _session(tmp_path)
    loop = SpecialistLoop(name="test", session=session, max_iterations=10)
    tool = _AbsentTool(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )
    await loop.run_tool(
        tool,
        _AbsentArgs(),
        artifact_family="test",
        summary_template="t: {tool} -> {invocation_id}",
    )

    raw = session.ledger.path.read_bytes().splitlines()
    kinds = [json.loads(line)["kind"] for line in raw]
    assert "tool_unavailable" in kinds
    assert "specialist_gave_up" in kinds
    # Tombstone invocation_id is present in the give-up entry
    give_up = next(
        json.loads(line) for line in raw if json.loads(line)["kind"] == "specialist_gave_up"
    )
    assert give_up["payload"]["reason"] == "tool_unavailable"
    assert give_up["payload"]["final_exit_code"] == -127
