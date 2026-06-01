"""Built-in orchestrator integration tests.

These exercise the cli triage path without spawning a real subprocess. We
stub each typed tool's execute() with an async function that returns a
synthetic Invocation, so the orchestrator's ledger emissions, specialist
sequencing, and replan accounting are verified without depending on the
SIFT toolchain.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest

import sworn.tools.registry as tools_registry
from sworn.agents.specialists import Synthesizer
from sworn.gateway.provenance import Invocation, new_invocation_id, sha256_bytes
from sworn.gateway.session import Session
from sworn.orchestration import TriagePaths, run_builtin_triage
from sworn.tools._base import ToolExecutionResult


@pytest.fixture()
def session(tmp_path: Path) -> Session:
    return Session.start(
        case_id="ORCH-001",
        case_root=tmp_path / "cases" / "ORCH-001",
        signing_key_path=tmp_path / "host.ed25519.pem",
    )


@pytest.fixture()
def stub_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every typed-tool execute() with a synthetic Invocation.

    This isolates the orchestrator from the SIFT binary search path so the
    test suite runs anywhere.
    """
    async def fake_execute(self, args):
        inv = Invocation(
            invocation_id=new_invocation_id(),
            seq=self.invocations.next_seq(),
            case_id=self.case_id,
            tool=self.name,
            args=tuple(self.build_argv(args)),
            stdout_sha256=sha256_bytes(b"stub-stdout"),
            stderr_sha256=sha256_bytes(b""),
            exit_code=0,
            latency_ms=1,
            started_at=Invocation.now(),
            finished_at=Invocation.now(),
            evidence_ids_read=(),
        )
        self.invocations.record(inv)
        self.ledger.append(
            "tool_invocation",
            {
                "case_id": self.case_id,
                "invocation_id": inv.invocation_id,
                "seq": inv.seq,
                "tool": inv.tool,
                "args": list(inv.args),
                "exit_code": 0,
                "stdout_sha256": inv.stdout_sha256,
                "stderr_sha256": inv.stderr_sha256,
                "latency_ms": 1,
                "started_at": inv.started_at.isoformat(timespec="microseconds"),
                "finished_at": inv.finished_at.isoformat(timespec="microseconds"),
                "evidence_ids_read": [],
            },
        )
        return ToolExecutionResult(
            invocation=inv,
            stdout_for_llm="<evidence>stub</evidence>",
            rendered_command="stub",
        )

    for cls in tools_registry.iter_tools():
        monkeypatch.setattr(cls, "execute", fake_execute, raising=True)


@pytest.mark.asyncio
async def test_memory_only_runs_memory_specialist_alone(
    session: Session, stub_tools, tmp_path: Path
) -> None:
    mem = tmp_path / "mem.raw"
    mem.write_bytes(b"x" * 4096)
    paths = TriagePaths(memory_image=mem)
    result = await run_builtin_triage(session, paths, max_iterations=10)
    assert result.specialists_run == ["memory", "network"]
    # Memory specialist runs 5 base plugins + dedicated malfind = 6 invocations
    # plus NetworkSpecialist's 2 volatility net plugins.
    assert result.observation_count >= 6
    assert result.halted_specialist is None


@pytest.mark.asyncio
async def test_disk_and_memory_runs_all_three(
    session: Session, stub_tools, tmp_path: Path
) -> None:
    disk = tmp_path / "disk.E01"
    disk.write_bytes(b"d" * 4096)
    mem = tmp_path / "mem.raw"
    mem.write_bytes(b"x" * 4096)
    paths = TriagePaths(disk_image=disk, memory_image=mem)
    result = await run_builtin_triage(session, paths, max_iterations=15)
    assert result.specialists_run == ["memory", "disk", "network"]
    assert result.halted_specialist is None


@pytest.mark.asyncio
async def test_ledger_records_orchestration_start_and_stop(
    session: Session, stub_tools, tmp_path: Path
) -> None:
    mem = tmp_path / "mem.raw"
    mem.write_bytes(b"m" * 1024)
    await run_builtin_triage(session, TriagePaths(memory_image=mem), max_iterations=10)
    raw = session.ledger.path.read_bytes().splitlines()
    kinds = [__import__("json").loads(line)["kind"] for line in raw]
    assert "orchestration_start" in kinds
    assert "orchestration_stop" in kinds
    # Order: session_start -> evidence_register -> orchestration_start -> ... -> orchestration_stop
    assert kinds.index("orchestration_start") < kinds.index("orchestration_stop")


def test_synthesizer_rejects_single_family_via_corroboration(
    session: Session, stub_tools, tmp_path: Path
) -> None:
    """If the Synthesizer proposes a finding citing observations all from
    one artifact family, the gateway demotes it to INDICATION. This is the
    moat #3 enforcement path under the multi-agent orchestration shape.
    """
    from sworn.agents.loop import Observation
    from sworn.findings.schema import FindingClass

    inv1 = Invocation(
        invocation_id=new_invocation_id(),
        seq=session.invocations.next_seq(),
        case_id=session.case_id,
        tool="prefetch_pecmd",
        args=("--demo",),
        stdout_sha256=sha256_bytes(b"a"),
        stderr_sha256=sha256_bytes(b""),
        exit_code=0,
        latency_ms=1,
        started_at=Invocation.now(),
        finished_at=Invocation.now(),
    )
    inv2 = Invocation(
        invocation_id=new_invocation_id(),
        seq=session.invocations.next_seq(),
        case_id=session.case_id,
        tool="prefetch_pecmd",
        args=("--demo2",),
        stdout_sha256=sha256_bytes(b"b"),
        stderr_sha256=sha256_bytes(b""),
        exit_code=0,
        latency_ms=1,
        started_at=Invocation.now(),
        finished_at=Invocation.now(),
    )
    session.invocations.record(inv1)
    session.invocations.record(inv2)

    obs = [
        Observation(
            specialist="disk",
            summary="prefetch hit 1",
            artifact_family="prefetch",
            invocation=inv1,
            confidence=0.9,
        ),
        Observation(
            specialist="disk",
            summary="prefetch hit 2",
            artifact_family="prefetch",
            invocation=inv2,
            confidence=0.9,
        ),
    ]
    result = Synthesizer(session).propose(
        host="ORCH",
        finding_class=FindingClass.execution,
        title="single family attempt",
        description="should be demoted to INDICATION",
        observations=obs,
    )
    # gateway returns a FindingAdmissionResult; check state
    from sworn.findings.schema import FindingState
    from sworn.gateway.constraint import FindingAdmissionResult

    assert isinstance(result, FindingAdmissionResult)
    assert result.state is FindingState.indication


def test_synthesizer_reaches_draft_with_two_families(
    session: Session, stub_tools, tmp_path: Path
) -> None:
    from sworn.agents.loop import Observation
    from sworn.findings.schema import FindingClass, FindingState
    from sworn.gateway.constraint import FindingAdmissionResult

    inv_pf = Invocation(
        invocation_id=new_invocation_id(),
        seq=session.invocations.next_seq(),
        case_id=session.case_id,
        tool="prefetch_pecmd",
        args=("--pf",),
        stdout_sha256=sha256_bytes(b"pf"),
        stderr_sha256=sha256_bytes(b""),
        exit_code=0,
        latency_ms=1,
        started_at=Invocation.now(),
        finished_at=Invocation.now(),
    )
    inv_am = Invocation(
        invocation_id=new_invocation_id(),
        seq=session.invocations.next_seq(),
        case_id=session.case_id,
        tool="registry_regripper",
        args=("--am",),
        stdout_sha256=sha256_bytes(b"am"),
        stderr_sha256=sha256_bytes(b""),
        exit_code=0,
        latency_ms=1,
        started_at=Invocation.now(),
        finished_at=Invocation.now(),
    )
    session.invocations.record(inv_pf)
    session.invocations.record(inv_am)
    obs = [
        Observation(
            specialist="disk",
            summary="prefetch",
            artifact_family="prefetch",
            invocation=inv_pf,
            confidence=0.9,
        ),
        Observation(
            specialist="disk",
            summary="amcache",
            artifact_family="amcache",
            invocation=inv_am,
            confidence=0.9,
        ),
    ]
    result = Synthesizer(session).propose(
        host="ORCH",
        finding_class=FindingClass.execution,
        title="two-family corroborated",
        description="should reach DRAFT",
        observations=obs,
    )
    assert isinstance(result, FindingAdmissionResult)
    assert result.state is FindingState.draft
