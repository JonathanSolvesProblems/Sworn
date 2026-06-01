"""EvtxECmd + Hayabusa typed wrappers.

EvtxECmd (Eric Zimmerman, .NET / dotnet) parses .evtx into CSV/JSON with
event-map decoding. Hayabusa runs 3,700+ Sigma rules over the same events
and emits MITRE-tagged detections. The pair gives a deterministic event view
plus a deterministic detection view.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class EvtxECmdArgs(ToolArgs):
    evtx_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Path to an .evtx file or directory of .evtx files."
    )
    output_format: Literal["csv", "json"] = Field(default="json")
    maps_dir: str | None = Field(
        default=None, description="Override path to EvtxECmd maps directory."
    )


@register_tool
class EvtxECmdTool(TypedTool):
    name = "evtx_parse"
    description = (
        "Run EvtxECmd on a Windows .evtx file or directory and return decoded "
        "event records. Use this before any reasoning about Windows event logs."
    )
    binary = "EvtxECmd"
    artifact_family = "evtx_records"
    Args = EvtxECmdArgs
    timeout_seconds = 30 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, EvtxECmdArgs)
        p = Path(args.evtx_path)
        return [p] if p.is_file() else []

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, EvtxECmdArgs)
        out_dir = self.analysis_root / "evtx_parsed"
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            "-f" if Path(args.evtx_path).is_file() else "-d",
            args.evtx_path,
        ]
        if args.output_format == "csv":
            argv += ["--csv", str(out_dir)]
        else:
            argv += ["--json", str(out_dir)]
        if args.maps_dir:
            argv += ["--maps", args.maps_dir]
        return argv


class HayabusaArgs(ToolArgs):
    evtx_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Path to an .evtx file or a directory of .evtx files."
    )
    min_level: Literal["low", "medium", "high", "critical"] = Field(default="medium")
    output_csv: str = Field(default="hayabusa.csv")


@register_tool
class HayabusaTool(TypedTool):
    name = "evtx_hayabusa_detect"
    description = (
        "Run Hayabusa Sigma-based detection over Windows .evtx data. Returns "
        "rule hits with MITRE ATT&CK mapping. Use after evtx_parse to convert "
        "raw events into typed detections."
    )
    binary = "hayabusa"
    artifact_family = "evtx_sigma_detections"
    Args = HayabusaArgs
    timeout_seconds = 30 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, HayabusaArgs)
        p = Path(args.evtx_path)
        return [p] if p.is_file() else []

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, HayabusaArgs)
        out_path = (self.analysis_root / args.output_csv).resolve()
        if not str(out_path).startswith(str(self.analysis_root)):
            raise ValueError("output_csv must resolve under ./analysis/")
        return [
            "csv-timeline",
            "-d" if Path(args.evtx_path).is_dir() else "-f",
            args.evtx_path,
            "-o",
            str(out_path),
            "-m",
            args.min_level,
            "--no-wizard",
            "--quiet",
        ]
