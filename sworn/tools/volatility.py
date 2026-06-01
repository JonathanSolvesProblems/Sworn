"""Volatility 3 typed wrappers.

Volatility 3 is the headline memory-analysis demo on the SIFT VM. Each plugin
is exposed as its own typed function so the orchestrator chooses by name, not
by free-form CLI flags. Output is requested as JSON via `-r json` for
deterministic parsing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool

PluginName = Literal[
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
    "windows.malfind.Malfind",
    "windows.dlllist.DllList",
    "windows.handles.Handles",
    "windows.registry.hivelist.HiveList",
    "windows.svcscan.SvcScan",
    "windows.modules.Modules",
    "windows.driverirp.DriverIrp",
    "windows.envars.Envars",
    "windows.filescan.FileScan",
    "windows.privileges.Privs",
]


class _VolBase(ToolArgs):
    memory_image: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Absolute path to the memory image (.raw/.dmp/.lime).",
    )
    output_format: Literal["json", "csv", "pretty"] = Field(default="json")


class VolatilityArgs(_VolBase):
    plugin: PluginName = Field(
        description="Volatility 3 Windows plugin to run. One per call.",
    )


@register_tool
class VolatilityTool(TypedTool):
    name = "memory_volatility_run"
    description = (
        "Run a Volatility 3 Windows plugin against a memory image. "
        "Returns the plugin's structured output. Choose plugin per question: "
        "pslist for processes, pstree for parent-child, netscan for sockets, "
        "malfind for injected code, svcscan for services, registry.hivelist "
        "for loaded hives."
    )
    binary = "vol"
    artifact_family = "volatility_memory"
    Args = VolatilityArgs

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, VolatilityArgs)
        return [Path(args.memory_image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, VolatilityArgs)
        return [
            "-f",
            args.memory_image,
            "-r",
            args.output_format,
            args.plugin,
        ]


class VolatilityMalfindArgs(_VolBase):
    pid: int | None = Field(default=None, description="Optional PID to scope to.")
    dump: bool = Field(default=False, description="Dump suspect regions to ./analysis/.")


@register_tool
class VolatilityMalfindTool(TypedTool):
    name = "memory_volatility_malfind"
    description = (
        "Run Volatility 3 windows.malfind.Malfind to detect injected or "
        "hidden code in process memory. Supports optional PID scoping and "
        "memory-region dumping to ./analysis/."
    )
    binary = "vol"
    artifact_family = "volatility_memory"
    Args = VolatilityMalfindArgs

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, VolatilityMalfindArgs)
        return [Path(args.memory_image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, VolatilityMalfindArgs)
        argv = ["-f", args.memory_image, "-r", args.output_format, "windows.malfind.Malfind"]
        if args.pid is not None:
            argv += ["--pid", str(args.pid)]
        if args.dump:
            dump_dir = self.analysis_root / "malfind_dumps"
            dump_dir.mkdir(parents=True, exist_ok=True)
            argv += ["--dump", "--dump-dir", str(dump_dir)]
        return argv
