"""plaso / log2timeline + psort typed wrappers.

plaso produces the super-timeline: every timestamped artifact across the disk
image in one ordered stream. Wrap log2timeline (which extracts) separately
from psort (which queries) so the orchestrator can do extract-then-query
without conflating the two.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class Log2TimelineArgs(ToolArgs):
    image: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Absolute path to the disk image or mount point."
    )
    storage_file: Annotated[str, StringConstraints(min_length=1)] = Field(
        default="timeline.plaso",
        description="Output .plaso storage file under ./analysis/.",
    )
    parsers: list[str] = Field(
        default_factory=lambda: ["win7", "webhist", "winreg"],
        description="Parser presets or named parsers (comma-passed to log2timeline).",
    )
    artifact_filters: list[str] = Field(
        default_factory=list,
        description="Optional list of artifact-definition names to limit scope.",
    )


@register_tool
class Log2TimelineTool(TypedTool):
    name = "timeline_log2timeline_extract"
    description = (
        "Run log2timeline.py to extract timestamped events from a disk image "
        "into a .plaso storage file. Use the win7 preset for Windows hosts. "
        "Pair with timeline_psort_query to ask questions of the result."
    )
    binary = "log2timeline.py"
    artifact_family = "plaso_supertimeline"
    Args = Log2TimelineArgs
    timeout_seconds = 60 * 60  # super-timelines can take a while

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, Log2TimelineArgs)
        return [Path(args.image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, Log2TimelineArgs)
        storage = (self.analysis_root / args.storage_file).resolve()
        if not str(storage).startswith(str(self.analysis_root)):
            raise ValueError("storage_file must resolve under ./analysis/")
        argv = ["--storage_file", str(storage)]
        if args.parsers:
            argv += ["--parsers", ",".join(args.parsers)]
        if args.artifact_filters:
            argv += ["--artifact_filters", ",".join(args.artifact_filters)]
        argv += [args.image]
        return argv


class PsortQueryArgs(ToolArgs):
    storage_file: Annotated[str, StringConstraints(min_length=1)]
    output_format: Literal["json_line", "l2tcsv", "dynamic"] = Field(default="json_line")
    time_slice: str | None = Field(
        default=None,
        description=(
            "Optional ISO 8601 timestamp; psort returns events within "
            "+/- time-slice-size minutes of this."
        ),
    )
    time_slice_size: int = Field(default=5, ge=1, le=1440)
    filter_expression: str | None = Field(
        default=None,
        description="Optional pfilter expression (e.g. 'parser is \\\"prefetch\\\"').",
    )

    @field_validator("time_slice")
    @classmethod
    def _parse_iso(cls, v: str | None) -> str | None:
        if v is None:
            return None
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


@register_tool
class PsortQueryTool(TypedTool):
    name = "timeline_psort_query"
    description = (
        "Run psort.py against a .plaso storage file. Use time_slice to focus "
        "on a moment of interest, filter_expression to scope by parser/source. "
        "Output is JSON-Line by default for structured ingestion."
    )
    binary = "psort.py"
    artifact_family = "plaso_supertimeline"
    Args = PsortQueryArgs
    timeout_seconds = 30 * 60

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, PsortQueryArgs)
        storage = Path(args.storage_file)
        if not storage.is_absolute():
            storage = (self.analysis_root / storage).resolve()
        argv = ["-o", args.output_format, "-w", "-"]
        if args.time_slice:
            argv += ["--slice", args.time_slice, "--slice_size", str(args.time_slice_size)]
        argv += [str(storage)]
        if args.filter_expression:
            argv += [args.filter_expression]
        return argv
