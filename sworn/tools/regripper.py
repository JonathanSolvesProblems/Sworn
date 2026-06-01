"""RegRipper typed wrapper.

RegRipper drives 600+ Perl plugins against Windows registry hives and emits
structured artifact data: autoruns, USB history, ShimCache, AppCompat,
UserAssist, BAM/DAM, and Run-key persistence. The orchestrator names a
plugin by string; the wrapper validates against a known-plugin allow-set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator

from sworn.tools._base import ToolArgs, TypedTool, register_tool

# Subset of RegRipper plugins most useful for triage; extend as needed.
KNOWN_PLUGINS: frozenset[str] = frozenset(
    {
        "amcache",
        "appcompatcache",
        "shimcache",
        "userassist",
        "bam",
        "syscache",
        "run",
        "runonce",
        "services",
        "tasks",
        "usbstor",
        "mountdev2",
        "wlan_events",
        "winlogon",
        "samparse",
        "compname",
        "timezone",
        "shellbags",
        "shellfolders",
        "trustrecords",
        "lastloggedon",
    }
)


class RegRipperArgs(ToolArgs):
    hive_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Path to a Windows registry hive (SYSTEM, SOFTWARE, NTUSER.DAT, ...)."
    )
    plugin: Annotated[str, StringConstraints(min_length=1, max_length=64)] = Field(
        description="RegRipper plugin name. Must be in the allow-set.",
    )

    @field_validator("plugin")
    @classmethod
    def _allowed(cls, v: str) -> str:
        if v not in KNOWN_PLUGINS:
            raise ValueError(
                f"plugin {v!r} not in SWORN allow-set. Known: "
                + ", ".join(sorted(KNOWN_PLUGINS))
            )
        return v


@register_tool
class RegRipperTool(TypedTool):
    name = "registry_regripper"
    description = (
        "Run a single RegRipper plugin against a Windows registry hive. "
        "Plugin must be in the SWORN allow-set (e.g. amcache, shimcache, "
        "userassist, run, services, tasks, usbstor)."
    )
    binary = "rip.pl"
    artifact_family = "registry"
    Args = RegRipperArgs
    timeout_seconds = 5 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, RegRipperArgs)
        return [Path(args.hive_path)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, RegRipperArgs)
        return ["-r", args.hive_path, "-p", args.plugin]
