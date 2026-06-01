"""Specialist agents.

Each specialist scopes its tool catalog narrowly so its LLM context never
holds full case evidence. Specialists stage Observations through SpecialistLoop
and never call gateway.submit. The Synthesizer reads pooled Observations and
proposes Findings the gateway then validates.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from sworn.agents.loop import Observation, SpecialistLoop
from sworn.findings.schema import (
    EvidenceCitation,
    Finding,
    FindingClass,
    Severity,
)
from sworn.gateway.constraint import (
    FindingAdmissionResult,
    FindingRejected,
)
from sworn.gateway.session import Session
from sworn.tools import registry as tools_registry
from sworn.tools._base import TypedTool
from sworn.tools.volatility import VolatilityArgs, VolatilityMalfindArgs
from sworn.tools.plaso import Log2TimelineArgs, PsortQueryArgs
from sworn.tools.evtx import EvtxECmdArgs, HayabusaArgs
from sworn.tools.mft import MFTArgs
from sworn.tools.regripper import RegRipperArgs
from sworn.tools.sleuthkit import FlsArgs, MmlsArgs
from sworn.tools.bulk_extractor import BulkExtractorArgs
from sworn.tools.pecmd import PECmdArgs
from sworn.tools.hindsight import HindsightArgs

log = logging.getLogger("sworn.agents.specialists")


def _tool(session: Session, name: str) -> TypedTool:
    cls = tools_registry.get_tool(name)
    if cls is None:
        raise RuntimeError(f"tool {name!r} not registered")
    return cls(
        case_id=session.case_id,
        invocations=session.invocations,
        evidence=session.evidence,
        ledger=session.ledger,
        analysis_root=session.analysis_root,
    )


class MemorySpecialist(SpecialistLoop):
    """Reasons only over memory artifacts via Volatility 3."""

    def __init__(self, session: Session, memory_image: Path, max_iterations: int = 15) -> None:
        super().__init__(name="memory", session=session, max_iterations=max_iterations)
        self.memory_image = str(memory_image)

    async def triage(self) -> Iterable[Observation]:
        plugins = [
            "windows.pslist.PsList",
            "windows.pstree.PsTree",
            "windows.cmdline.CmdLine",
            "windows.netscan.NetScan",
            "windows.svcscan.SvcScan",
        ]
        for plugin in plugins:
            tool = _tool(self.session, "memory_volatility_run")
            await self.run_tool(
                tool,
                VolatilityArgs(memory_image=self.memory_image, plugin=plugin),
                artifact_family="volatility_memory",
                summary_template="memory: ran {tool} -> {invocation_id}",
            )
        malfind = _tool(self.session, "memory_volatility_malfind")
        await self.run_tool(
            malfind,
            VolatilityMalfindArgs(memory_image=self.memory_image, dump=False),
            artifact_family="volatility_memory",
            summary_template="memory: ran {tool} -> {invocation_id}",
        )
        return self.observations


class DiskSpecialist(SpecialistLoop):
    """Reasons over disk artifacts via Sleuth Kit, plaso, RegRipper, PECmd."""

    def __init__(
        self,
        session: Session,
        disk_image: Path,
        *,
        mft_path: Path | None = None,
        registry_hives: dict[str, Path] | None = None,
        prefetch_dir: Path | None = None,
        chrome_profile: Path | None = None,
        max_iterations: int = 30,
    ) -> None:
        super().__init__(name="disk", session=session, max_iterations=max_iterations)
        self.disk_image = str(disk_image)
        self.mft_path = mft_path
        self.registry_hives = registry_hives or {}
        self.prefetch_dir = prefetch_dir
        self.chrome_profile = chrome_profile

    async def triage(self) -> Iterable[Observation]:
        # 1) partition table
        await self.run_tool(
            _tool(self.session, "fs_mmls"),
            MmlsArgs(image=self.disk_image),
            artifact_family="sleuthkit_fs",
            summary_template="disk: ran {tool} -> {invocation_id}",
        )
        # 2) recursive fls bodyfile
        await self.run_tool(
            _tool(self.session, "fs_fls"),
            FlsArgs(image=self.disk_image, recursive=True, output_bodyfile=True),
            artifact_family="sleuthkit_fs",
            summary_template="disk: ran {tool} -> {invocation_id}",
        )
        # 3) MFT parse if available
        if self.mft_path:
            await self.run_tool(
                _tool(self.session, "mft_parse"),
                MFTArgs(mft_path=str(self.mft_path), output_format="csv"),
                artifact_family="mft_records",
                summary_template="disk: ran {tool} -> {invocation_id}",
            )
        # 4) registry plugins covering core artifact families
        plugin_to_family = {
            "amcache": "amcache",
            "appcompatcache": "shimcache",
            "userassist": "userassist",
            "bam": "bam_dam",
            "run": "run_key",
            "runonce": "run_key",
            "services": "service_install",
            "tasks": "scheduled_task",
            "usbstor": "registry",
        }
        for plugin, family in plugin_to_family.items():
            hive = self._hive_for(plugin)
            if not hive:
                continue
            await self.run_tool(
                _tool(self.session, "registry_regripper"),
                RegRipperArgs(hive_path=str(hive), plugin=plugin),
                artifact_family=family,
                summary_template="disk: ran {tool} -> {invocation_id}",
            )
        # 5) prefetch
        if self.prefetch_dir:
            await self.run_tool(
                _tool(self.session, "prefetch_pecmd"),
                PECmdArgs(prefetch_path=str(self.prefetch_dir), output_format="json"),
                artifact_family="prefetch",
                summary_template="disk: ran {tool} -> {invocation_id}",
            )
        # 6) browser
        if self.chrome_profile:
            await self.run_tool(
                _tool(self.session, "browser_hindsight"),
                HindsightArgs(profile_path=str(self.chrome_profile)),
                artifact_family="browser_chromium",
                summary_template="disk: ran {tool} -> {invocation_id}",
            )
        # 7) plaso super-timeline
        await self.run_tool(
            _tool(self.session, "timeline_log2timeline_extract"),
            Log2TimelineArgs(image=self.disk_image, storage_file="timeline.plaso"),
            artifact_family="plaso_supertimeline",
            summary_template="disk: ran {tool} -> {invocation_id}",
        )
        await self.run_tool(
            _tool(self.session, "timeline_psort_query"),
            PsortQueryArgs(
                storage_file=str(self.session.analysis_root / "timeline.plaso"),
                output_format="json_line",
                filter_expression='parser is "prefetch" or parser is "winreg"',
            ),
            artifact_family="plaso_supertimeline",
            summary_template="disk: ran {tool} -> {invocation_id}",
        )
        return self.observations

    def _hive_for(self, plugin: str) -> Path | None:
        if plugin in {"amcache"}:
            return self.registry_hives.get("AMCACHE")
        if plugin in {"appcompatcache", "services", "usbstor"}:
            return self.registry_hives.get("SYSTEM")
        if plugin in {"userassist", "run", "runonce"}:
            return self.registry_hives.get("NTUSER")
        if plugin in {"tasks", "bam"}:
            return self.registry_hives.get("SYSTEM")
        return None


class NetworkSpecialist(SpecialistLoop):
    """Carves network indicators and queries memory net artifacts."""

    def __init__(
        self,
        session: Session,
        *,
        disk_image: Path | None,
        memory_image: Path | None,
        evtx_path: Path | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(name="network", session=session, max_iterations=max_iterations)
        self.disk_image = str(disk_image) if disk_image else None
        self.memory_image = str(memory_image) if memory_image else None
        self.evtx_path = evtx_path

    async def triage(self) -> Iterable[Observation]:
        if self.disk_image:
            await self.run_tool(
                _tool(self.session, "carve_bulk_extractor"),
                BulkExtractorArgs(
                    image=self.disk_image,
                    enable_scanners=["email", "url", "domain", "httpheader"],
                ),
                artifact_family="bulk_extractor_features",
                summary_template="network: ran {tool} -> {invocation_id}",
            )
        if self.memory_image:
            await self.run_tool(
                _tool(self.session, "memory_volatility_run"),
                VolatilityArgs(
                    memory_image=self.memory_image,
                    plugin="windows.netscan.NetScan",
                ),
                artifact_family="volatility_memory",
                summary_template="network: ran {tool} -> {invocation_id}",
            )
            await self.run_tool(
                _tool(self.session, "memory_volatility_run"),
                VolatilityArgs(
                    memory_image=self.memory_image,
                    plugin="windows.netstat.NetStat",
                ),
                artifact_family="volatility_memory",
                summary_template="network: ran {tool} -> {invocation_id}",
            )
        if self.evtx_path:
            await self.run_tool(
                _tool(self.session, "evtx_hayabusa_detect"),
                HayabusaArgs(evtx_path=str(self.evtx_path), min_level="medium"),
                artifact_family="evtx_sigma_detections",
                summary_template="network: ran {tool} -> {invocation_id}",
                success_predicate=lambda r: r.invocation.exit_code in (0, 1),
            )
        return self.observations


class Synthesizer:
    """Reads pooled Observations and proposes Findings to the gateway.

    The Synthesizer is the only specialist allowed to call gateway.submit. It
    converts an Observation set into a candidate Finding whose backing
    invocations span at least two distinct artifact families (so the gateway's
    corroboration check passes).
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def propose(
        self,
        *,
        host: str,
        finding_class: FindingClass,
        title: str,
        description: str,
        observations: list[Observation],
        severity: Severity = Severity.high,
        mitre: list[str] | None = None,
    ) -> FindingAdmissionResult | FindingRejected:
        citations: list[EvidenceCitation] = []
        for obs in observations:
            citations.append(
                EvidenceCitation(
                    invocation_id=obs.invocation.invocation_id,
                    tool=obs.invocation.tool,
                    artifact_family=obs.artifact_family,
                    stdout_sha256=obs.invocation.stdout_sha256,
                    excerpt=obs.summary[:512],
                )
            )
        finding = Finding(
            case_id=self.session.case_id,
            host=host,
            finding_class=finding_class,
            severity=severity,
            title=title,
            description=description,
            backing_invocations=citations,
            mitre_techniques=mitre or [],
            confidence=0.8,
        )
        try:
            return self.session.gateway.submit(finding)
        except FindingRejected as e:
            return e


__all__ = [
    "MemorySpecialist",
    "DiskSpecialist",
    "NetworkSpecialist",
    "Synthesizer",
]
