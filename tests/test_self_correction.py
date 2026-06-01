"""Self-correction loop tests using a stub tool.

We exercise SpecialistLoop without spinning up a real subprocess by using a
TypedTool subclass whose binary is `echo` and a success_predicate that
intentionally fails the first attempt to drive a replan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydantic import Field

from sworn.agents.loop import SelfCorrectionExceeded, SpecialistLoop
from sworn.gateway.session import Session
from sworn.tools._base import ToolArgs, TypedTool


import sys


class _StubArgs(ToolArgs):
    msg: str = Field(default="ok")


class _StubTool(TypedTool):
    name = "_stub_echo"
    description = "echo for tests"
    # Use the current Python interpreter so this test runs on any host where
    # pytest itself runs (Windows, Linux, the SIFT VM).
    binary = sys.executable
    artifact_family = "test"
    Args = _StubArgs

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, _StubArgs)
        return ["-c", f"print({args.msg!r})"]


def _session(tmp_path: Path) -> Session:
    return Session.start(
        case_id="LOOP-001",
        case_root=tmp_path / "cases" / "LOOP-001",
        signing_key_path=tmp_path / "host.ed25519.pem",
    )


@pytest.mark.asyncio
async def test_loop_records_observation_on_success(tmp_path: Path) -> None:
    session = _session(tmp_path)
    loop = SpecialistLoop(name="t", session=session, max_iterations=5)
    tool = _StubTool(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )
    await loop.run_tool(
        tool,
        _StubArgs(msg="hello"),
        artifact_family="test",
        summary_template="t: {tool} -> {invocation_id}",
    )
    assert len(loop.observations) == 1
    assert len(loop.replans) == 0


@pytest.mark.asyncio
async def test_loop_replans_and_gives_up(tmp_path: Path) -> None:
    session = _session(tmp_path)
    loop = SpecialistLoop(name="t", session=session, max_iterations=10)
    tool = _StubTool(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )

    # Force "failure" by an always-false predicate.
    def replan(_result, current_args):
        return {"msg": current_args["msg"] + "!"}

    result = await loop.run_tool(
        tool,
        _StubArgs(msg="hi"),
        artifact_family="test",
        summary_template="t: {tool} -> {invocation_id}",
        success_predicate=lambda _r: False,
        max_retries=2,
        replan_args=replan,
    )
    # max_retries=2 means initial attempt + 2 replans = 3 total
    assert len(loop.replans) >= 2
    # And no observation since success_predicate never True
    assert len(loop.observations) == 0
    assert result.invocation.exit_code == 0  # `echo` itself succeeded


@pytest.mark.asyncio
async def test_loop_hits_max_iterations(tmp_path: Path) -> None:
    session = _session(tmp_path)
    loop = SpecialistLoop(name="t", session=session, max_iterations=2)
    tool = _StubTool(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )
    with pytest.raises(SelfCorrectionExceeded):
        # 3 attempts with max_iterations=2 => raises on the 3rd
        for _ in range(3):
            await loop.run_tool(
                tool,
                _StubArgs(msg="x"),
                artifact_family="test",
                summary_template="t: {tool} -> {invocation_id}",
            )
