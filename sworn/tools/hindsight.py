"""Hindsight typed wrapper.

Hindsight parses Chromium-based browser artifacts (history, downloads,
cookies, autofill, cache). Most IR cases involve a browser-borne initial
access vector, so it earns its slot in the typed catalog.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class HindsightArgs(ToolArgs):
    profile_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description=(
            "Path to a Chromium-family user data dir (e.g. "
            "C:/Users/<user>/AppData/Local/Google/Chrome/User Data/Default)."
        ),
    )
    output_format: Literal["jsonl", "xlsx", "sqlite"] = Field(default="jsonl")
    output_subdir: Annotated[str, StringConstraints(min_length=1)] = Field(
        default="hindsight"
    )


@register_tool
class HindsightTool(TypedTool):
    name = "browser_hindsight"
    description = (
        "Run Hindsight against a Chromium-family browser profile directory. "
        "Returns history, downloads, cookies, autofill, and cache analysis. "
        "Use after extracting the profile dir from the disk image."
    )
    binary = "hindsight.py"
    artifact_family = "browser_chromium"
    Args = HindsightArgs
    timeout_seconds = 10 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, HindsightArgs)
        p = Path(args.profile_path)
        return [p] if p.is_file() else []

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, HindsightArgs)
        out_dir = (self.analysis_root / args.output_subdir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = ["-i", args.profile_path, "-o", str(out_dir / "hindsight"), "-f", args.output_format]
        return argv
