"""The Sleuth Kit typed wrappers (fls, icat, mmls, mactime).

Filesystem-level enumeration of an E01/raw image. fls walks entries, icat
extracts a single file by inode, mmls prints partition tables, mactime turns
a bodyfile into a timeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, StringConstraints

from sworn.tools._base import ToolArgs, TypedTool, register_tool


class FlsArgs(ToolArgs):
    image: Annotated[str, StringConstraints(min_length=1)]
    offset_sectors: int = Field(default=0, ge=0)
    recursive: bool = Field(default=True)
    output_bodyfile: bool = Field(default=True, description="Emit timestamps as bodyfile.")
    inode: int | None = Field(default=None, description="Optional starting inode.")


@register_tool
class FlsTool(TypedTool):
    name = "fs_fls"
    description = (
        "Walk a filesystem image with The Sleuth Kit's fls. Use recursive=true "
        "for a full listing or set an inode to scope. With output_bodyfile, "
        "feed the result to fs_mactime for a deterministic FS timeline."
    )
    binary = "fls"
    artifact_family = "sleuthkit_fs"
    Args = FlsArgs
    timeout_seconds = 30 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, FlsArgs)
        return [Path(args.image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, FlsArgs)
        argv: list[str] = []
        if args.offset_sectors:
            argv += ["-o", str(args.offset_sectors)]
        if args.recursive:
            argv.append("-r")
        if args.output_bodyfile:
            argv.append("-m")
            argv.append("/")
        argv.append(args.image)
        if args.inode is not None:
            argv.append(str(args.inode))
        return argv


class IcatArgs(ToolArgs):
    image: Annotated[str, StringConstraints(min_length=1)]
    inode: int = Field(ge=0)
    offset_sectors: int = Field(default=0, ge=0)


@register_tool
class IcatTool(TypedTool):
    name = "fs_icat"
    description = (
        "Extract a single file by inode from a filesystem image with The "
        "Sleuth Kit's icat. The extracted bytes are returned as the tool "
        "stdout (truncated for the LLM; full content available via the "
        "ledger by invocation_id)."
    )
    binary = "icat"
    artifact_family = "sleuthkit_fs"
    Args = IcatArgs
    timeout_seconds = 5 * 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, IcatArgs)
        return [Path(args.image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, IcatArgs)
        argv: list[str] = []
        if args.offset_sectors:
            argv += ["-o", str(args.offset_sectors)]
        argv += [args.image, str(args.inode)]
        return argv


class MmlsArgs(ToolArgs):
    image: Annotated[str, StringConstraints(min_length=1)]


@register_tool
class MmlsTool(TypedTool):
    name = "fs_mmls"
    description = "Print the partition table of a disk image."
    binary = "mmls"
    artifact_family = "sleuthkit_fs"
    Args = MmlsArgs
    timeout_seconds = 60

    def evidence_inputs(self, args):  # type: ignore[override]
        assert isinstance(args, MmlsArgs)
        return [Path(args.image)]

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, MmlsArgs)
        return [args.image]


class MactimeArgs(ToolArgs):
    bodyfile: Annotated[str, StringConstraints(min_length=1)]
    after: str | None = Field(default=None, description="ISO 8601 lower bound (UTC).")
    before: str | None = Field(default=None, description="ISO 8601 upper bound (UTC).")


@register_tool
class MactimeTool(TypedTool):
    name = "fs_mactime"
    description = (
        "Sort a Sleuth Kit bodyfile into a chronological timeline. Optionally "
        "scope with after/before."
    )
    binary = "mactime"
    artifact_family = "sleuthkit_fs"
    Args = MactimeArgs
    timeout_seconds = 5 * 60

    def build_argv(self, args):  # type: ignore[override]
        assert isinstance(args, MactimeArgs)
        argv = ["-b", args.bodyfile, "-d"]
        if args.after and args.before:
            argv += [f"{args.after}..{args.before}"]
        elif args.after:
            argv += [f"{args.after}.."]
        elif args.before:
            argv += [f"..{args.before}"]
        return argv
