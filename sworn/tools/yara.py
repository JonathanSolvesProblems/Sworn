"""YARA typed wrapper.

YARA matches signatures against files or memory. SWORN ships no rules in this
repo (third-party licensing). install.sh fetches Florian Roth's signature-base
to ./sworn/rules/ if the operator accepts the upstream CC BY-NC 4.0 license.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class YaraArgs(ToolArgs):
    rules_path: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="Path to a .yar/.yara file or a directory of rules."
    )
    target: Annotated[str, StringConstraints(min_length=1)] = Field(
        description="File, directory, or memory image to scan."
    )
    recursive: bool = Field(default=True)
    fast_match: bool = Field(default=True)
    print_strings: bool = Field(default=False, description="Include matched strings.")
    timeout_per_rule_s: int = Field(default=60, ge=1, le=600)
    threads: int = Field(default=4, ge=1, le=64)


@register_tool
class YaraTool(TypedTool):
    name = "malware_yara_scan"
    description = (
        "Scan a file, directory, or memory image with a YARA ruleset. Returns "
        "rule hits as one line per match (rule namespace, rule name, target). "
        "Pair with malware family rules (Florian Roth signature-base, etc.)."
    )
    binary = "yara"
    artifact_family = "yara_hits"
    Args = YaraArgs
    timeout_seconds = 30 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, YaraArgs)
        p = Path(args.target)
        return [p] if p.is_file() else []

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, YaraArgs)
        argv: list[str] = []
        if args.recursive:
            argv.append("-r")
        if args.fast_match:
            argv.append("-f")
        if args.print_strings:
            argv.append("-s")
        argv += ["-p", str(args.threads), "-a", str(args.timeout_per_rule_s)]
        argv += [args.rules_path, args.target]
        return argv
