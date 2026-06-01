"""bulk_extractor typed wrapper.

bulk_extractor carves features (emails, URLs, IPs, credit cards, BTC
addresses, AES keys, JSON blobs) from raw images at high speed. Its output
is per-feature text files in an output directory which the orchestrator
can then read selectively.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool

# Scanners shipped with bulk_extractor that are safe and useful for triage.
KNOWN_SCANNERS: frozenset[str] = frozenset(
    {
        "accts",
        "aes",
        "base64",
        "domain",
        "email",
        "exif",
        "gps",
        "httpheader",
        "json",
        "kml",
        "outlook",
        "pdf",
        "rar",
        "url",
        "vcard",
        "windirs",
        "winpe",
        "winprefetch",
        "zip",
    }
)


class BulkExtractorArgs(ToolArgs):
    image: Annotated[str, StringConstraints(min_length=1)]
    output_subdir: Annotated[str, StringConstraints(min_length=1, max_length=64)] = Field(
        default="bulk_extractor",
        description="Subdirectory under ./analysis/ for the bulk_extractor report.",
    )
    enable_scanners: list[str] = Field(default_factory=list)
    disable_scanners: list[str] = Field(default_factory=list)


@register_tool
class BulkExtractorTool(TypedTool):
    name = "carve_bulk_extractor"
    description = (
        "Carve features (emails, URLs, IPs, credit cards, BTC, AES keys, "
        "JSON, etc.) from a raw disk or memory image. Output is per-feature "
        "text files under ./analysis/<output_subdir>/."
    )
    binary = "bulk_extractor"
    artifact_family = "bulk_extractor_features"
    Args = BulkExtractorArgs
    timeout_seconds = 60 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, BulkExtractorArgs)
        return [Path(args.image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, BulkExtractorArgs)
        out_dir = (self.analysis_root / args.output_subdir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        if not str(out_dir).startswith(str(self.analysis_root)):
            raise ValueError("output_subdir must resolve under ./analysis/")

        for s in args.enable_scanners + args.disable_scanners:
            if s not in KNOWN_SCANNERS:
                raise ValueError(
                    f"unknown bulk_extractor scanner: {s!r}. "
                    f"Allowed: {', '.join(sorted(KNOWN_SCANNERS))}"
                )

        argv: list[str] = ["-o", str(out_dir)]
        for s in args.enable_scanners:
            argv += ["-e", s]
        for s in args.disable_scanners:
            argv += ["-x", s]
        argv += [args.image]
        return argv
