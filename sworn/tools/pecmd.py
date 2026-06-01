"""PECmd typed wrapper.

Windows Prefetch files (.pf) are the canonical evidence of program execution
in user mode. PECmd (Eric Zimmerman) parses them with run counts, last-run
timestamps, and referenced files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class PECmdArgs(ToolArgs):
    prefetch_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Path to a .pf file or a Prefetch directory."
    )
    output_format: Literal["csv", "json"] = Field(default="json")


@register_tool
class PECmdTool(TypedTool):
    name = "prefetch_pecmd"
    description = (
        "Parse Windows Prefetch (.pf) artifacts with PECmd. Returns one record "
        "per .pf with run count, last-run timestamps, and referenced file list. "
        "Use as deterministic evidence of program execution."
    )
    binary = "PECmd"
    artifact_family = "prefetch"
    Args = PECmdArgs
    timeout_seconds = 10 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, PECmdArgs)
        p = Path(args.prefetch_path)
        return [p] if p.is_file() else []

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, PECmdArgs)
        out_dir = self.analysis_root / "prefetch"
        out_dir.mkdir(parents=True, exist_ok=True)
        is_file = Path(args.prefetch_path).is_file()
        argv = ["-f" if is_file else "-d", args.prefetch_path]
        if args.output_format == "csv":
            argv += ["--csv", str(out_dir)]
        else:
            argv += ["--json", str(out_dir)]
        return argv
