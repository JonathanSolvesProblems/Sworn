"""Built-in orchestrator.

Deterministically walks every typed-tool specialist against a Session. Used by
`sworn triage` to produce a reproducible ledger without depending on an
external LLM client. Judges can run this end to end on the SIFT VM and
inspect the full `actions.jsonl`.

The LLM-driven path (`sworn gateway`) is what produces analytical findings;
the built-in orchestrator's job is to demonstrate the gateway works,
populate the corroboration-ready Observation pool, and emit the audit trail
the accuracy harness scores against.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

from sworn.agents.loop import SelfCorrectionExceeded
from sworn.agents.specialists import (
    DiskSpecialist,
    MemorySpecialist,
    NetworkSpecialist,
    Synthesizer,
)
from sworn.gateway.session import Session

log = logging.getLogger("sworn.orchestration")


@dataclass
class TriagePaths:
    disk_image: Path | None = None
    memory_image: Path | None = None
    mft: Path | None = None
    prefetch_dir: Path | None = None
    chrome_profile: Path | None = None
    evtx_path: Path | None = None
    system_hive: Path | None = None
    software_hive: Path | None = None
    ntuser_hive: Path | None = None
    amcache_hive: Path | None = None

    def registry_hives(self) -> dict[str, Path]:
        d: dict[str, Path] = {}
        if self.system_hive:
            d["SYSTEM"] = self.system_hive
        if self.software_hive:
            d["SOFTWARE"] = self.software_hive
        if self.ntuser_hive:
            d["NTUSER"] = self.ntuser_hive
        if self.amcache_hive:
            d["AMCACHE"] = self.amcache_hive
        return d


@dataclass
class TriageResult:
    case_id: str
    observation_count: int
    replan_count: int
    specialists_run: list[str]
    halted_specialist: str | None = None
    halted_reason: str | None = None


async def run_builtin_triage(
    session: Session,
    paths: TriagePaths,
    *,
    max_iterations: int = 30,
) -> TriageResult:
    """Walk every applicable specialist for the given session.

    The specialists each have their own per-loop max_iterations cap. The
    function-level cap here is forwarded to each specialist so a single
    --max-iterations flag governs the whole run.
    """
    specialists_run: list[str] = []
    total_obs = 0
    total_replans = 0
    halted: str | None = None
    halted_reason: str | None = None

    session.ledger.append(
        "orchestration_start",
        {
            "case_id": session.case_id,
            "mode": "builtin",
            "max_iterations": max_iterations,
            "paths": {
                "disk_image": str(paths.disk_image) if paths.disk_image else None,
                "memory_image": str(paths.memory_image) if paths.memory_image else None,
                "mft": str(paths.mft) if paths.mft else None,
                "prefetch_dir": str(paths.prefetch_dir) if paths.prefetch_dir else None,
                "chrome_profile": str(paths.chrome_profile) if paths.chrome_profile else None,
                "evtx_path": str(paths.evtx_path) if paths.evtx_path else None,
                "registry_hives": list(paths.registry_hives().keys()),
            },
        },
    )

    if paths.memory_image:
        spec = MemorySpecialist(session, paths.memory_image, max_iterations=max_iterations)
        try:
            await spec.triage()
        except SelfCorrectionExceeded as e:
            halted, halted_reason = "memory", str(e)
        specialists_run.append("memory")
        total_obs += len(spec.observations)
        total_replans += len(spec.replans)

    if paths.disk_image:
        spec = DiskSpecialist(
            session,
            paths.disk_image,
            mft_path=paths.mft,
            registry_hives=paths.registry_hives(),
            prefetch_dir=paths.prefetch_dir,
            chrome_profile=paths.chrome_profile,
            max_iterations=max_iterations,
        )
        try:
            await spec.triage()
        except SelfCorrectionExceeded as e:
            if halted is None:
                halted, halted_reason = "disk", str(e)
        specialists_run.append("disk")
        total_obs += len(spec.observations)
        total_replans += len(spec.replans)

    if True:
        net = NetworkSpecialist(
            session,
            disk_image=paths.disk_image,
            memory_image=paths.memory_image,
            evtx_path=paths.evtx_path,
            max_iterations=max_iterations,
        )
        try:
            await net.triage()
        except SelfCorrectionExceeded as e:
            if halted is None:
                halted, halted_reason = "network", str(e)
        specialists_run.append("network")
        total_obs += len(net.observations)
        total_replans += len(net.replans)

    session.ledger.append(
        "orchestration_stop",
        {
            "case_id": session.case_id,
            "specialists_run": specialists_run,
            "observation_count": total_obs,
            "replan_count": total_replans,
            "halted_specialist": halted,
            "halted_reason": halted_reason,
        },
    )

    return TriageResult(
        case_id=session.case_id,
        observation_count=total_obs,
        replan_count=total_replans,
        specialists_run=specialists_run,
        halted_specialist=halted,
        halted_reason=halted_reason,
    )


def run_builtin_triage_sync(
    session: Session, paths: TriagePaths, *, max_iterations: int = 30
) -> TriageResult:
    return asyncio.run(run_builtin_triage(session, paths, max_iterations=max_iterations))


__all__ = [
    "TriagePaths",
    "TriageResult",
    "run_builtin_triage",
    "run_builtin_triage_sync",
    "Synthesizer",
]
