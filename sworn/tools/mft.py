"""MFTECmd typed wrapper.

The NTFS Master File Table is the authoritative record of files that have
existed on the volume. MFTECmd (Eric Zimmerman) parses $MFT into CSV or
bodyfile with deterministic timestamps from both $STANDARD_INFORMATION and
$FILE_NAME so timestomping is detectable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class MFTArgs(ToolArgs):
    mft_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Path to the $MFT file extracted from the image."
    )
    output_format: Literal["csv", "bodyfile", "json"] = Field(default="csv")
    include_deleted_only: bool = Field(default=False)


@register_tool
class MFTTool(TypedTool):
    name = "mft_parse"
    description = (
        "Parse an NTFS $MFT with MFTECmd. Returns one record per file with "
        "$SI and $FN timestamps. Use --include_deleted_only to scope to "
        "tombstoned entries for evidence of staged or removed payloads."
    )
    binary = "MFTECmd"
    artifact_family = "mft_records"
    Args = MFTArgs
    timeout_seconds = 30 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, MFTArgs)
        return [Path(args.mft_path)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, MFTArgs)
        out_dir = self.analysis_root / "mft"
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = ["-f", args.mft_path]
        if args.output_format == "csv":
            argv += ["--csv", str(out_dir)]
        elif args.output_format == "json":
            argv += ["--json", str(out_dir)]
        else:
            argv += ["--body", str(out_dir / "mft.body")]
        if args.include_deleted_only:
            argv += ["--dr"]
        return argv
