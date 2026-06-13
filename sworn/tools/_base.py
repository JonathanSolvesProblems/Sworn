"""Base class for typed MCP tool wrappers.

Every SIFT tool surfaced to the orchestrator is a TypedTool subclass with a
pydantic ToolArgs schema. There is no generic `execute_shell_cmd`. The agent
physically cannot invoke a binary the gateway has not wrapped here.

Each TypedTool subclass declares:
  - name           : the MCP function name the orchestrator sees
  - description    : a sentence the orchestrator uses to decide when to call it
  - binary         : absolute path on the SIFT VM
  - artifact_family: which corroboration family this tool contributes to
  - Args           : pydantic model for the parameters

The base class handles subprocess execution, hashing, evidence read-tracking,
sanitization for the LLM, ledger emission, and invocation recording.
"""

from __future__ import annotations

import asyncio
import shlex
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Iterable

from pydantic import BaseModel

from sworn.gateway.evidence import EvidenceRegistry, RegisteredEvidence
from sworn.gateway.ledger import Ledger
from sworn.gateway.provenance import (
    Invocation,
    InvocationStore,
    new_invocation_id,
    sha256_bytes,
)
from sworn.injection_defense import wrap_evidence


class ToolArgs(BaseModel):
    """Marker base for tool argument schemas."""

    model_config = {"extra": "forbid"}


@dataclass(frozen=True)
class ToolExecutionResult:
    invocation: Invocation
    stdout_for_llm: str
    rendered_command: str


_REGISTRY: dict[str, type["TypedTool"]] = {}


def register_tool(cls: type["TypedTool"]) -> type["TypedTool"]:
    if cls.name in _REGISTRY:
        raise RuntimeError(f"tool {cls.name!r} already registered")
    _REGISTRY[cls.name] = cls
    return cls


def iter_tools() -> Iterable[type["TypedTool"]]:
    return _REGISTRY.values()


def get_tool(name: str) -> type["TypedTool"] | None:
    return _REGISTRY.get(name)


class TypedTool(ABC):
    """Base class for a SIFT-tool MCP wrapper."""

    name: ClassVar[str]
    description: ClassVar[str]
    binary: ClassVar[str]
    artifact_family: ClassVar[str]
    Args: ClassVar[type[ToolArgs]]

    timeout_seconds: ClassVar[int] = 600
    stdout_truncate_bytes: ClassVar[int] = 64 * 1024  # what the LLM sees

    def __init__(
        self,
        *,
        case_id: str,
        invocations: InvocationStore,
        evidence: EvidenceRegistry,
        ledger: Ledger,
        analysis_root: Path,
    ) -> None:
        self.case_id = case_id
        self.invocations = invocations
        self.evidence = evidence
        self.ledger = ledger
        self.analysis_root = analysis_root.resolve()

    @abstractmethod
    def build_argv(self, args: ToolArgs) -> list[str]:
        """Return the argv list. self.binary is prepended automatically."""

    def evidence_inputs(self, args: ToolArgs) -> list[Path]:
        """Override to declare which evidence files this call reads."""
        return []

    def preflight(self, args: ToolArgs) -> None:
        """Override to add per-tool checks before the binary runs."""
        return None

    async def execute(self, args: ToolArgs) -> ToolExecutionResult:
        self.preflight(args)
        evidence_reads: list[RegisteredEvidence] = []
        for p in self.evidence_inputs(args):
            ev = self.evidence.get_by_path(p) or self.evidence.register(p)
            evidence_reads.append(ev)

        argv_tail = self.build_argv(args)

        if not shutil.which(self.binary) and not Path(self.binary).exists():
            # Binary unavailable. Emit a tombstone invocation so the audit
            # trail still records the attempt; the SpecialistLoop checks
            # for exit_code=-127 and gives up gracefully instead of
            # retrying a binary that will never appear. This is the
            # defensive layer that lets SWORN survive a partial SIFT
            # install or a single missing tool on the runner.
            seq = self.invocations.next_seq()
            now = Invocation.now()
            stderr_body = f"binary not found on PATH: {self.binary}".encode("utf-8")
            inv = Invocation(
                invocation_id=new_invocation_id(),
                seq=seq,
                case_id=self.case_id,
                tool=self.name,
                args=tuple(argv_tail),
                stdout_sha256=sha256_bytes(b""),
                stderr_sha256=sha256_bytes(stderr_body),
                exit_code=-127,
                latency_ms=0,
                started_at=now,
                finished_at=now,
                evidence_ids_read=tuple(ev.evidence_id for ev in evidence_reads),
            )
            self.invocations.record(inv)
            self.ledger.append(
                "tool_unavailable",
                {
                    "case_id": self.case_id,
                    "invocation_id": inv.invocation_id,
                    "seq": inv.seq,
                    "tool": inv.tool,
                    "expected_binary": self.binary,
                    "evidence_ids_read": list(inv.evidence_ids_read),
                },
            )
            wrapped = wrap_evidence(
                body=f"[tool {self.name!r} binary {self.binary!r} not found on PATH]",
                tool=self.name,
                invocation_id=inv.invocation_id,
                bytes_seen=0,
            )
            return ToolExecutionResult(
                invocation=inv,
                stdout_for_llm=wrapped,
                rendered_command=f"# unavailable: {self.binary}",
            )

        argv = [self.binary, *argv_tail]
        rendered = " ".join(shlex.quote(a) for a in argv)
        seq = self.invocations.next_seq()
        started = Invocation.now()
        t0 = time.monotonic()

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.analysis_root),
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            proc.kill()
            stdout_b, stderr_b = await proc.communicate()
            exit_code = -1
        else:
            exit_code = proc.returncode if proc.returncode is not None else -1
        latency_ms = int((time.monotonic() - t0) * 1000)
        finished = Invocation.now()

        # Re-verify evidence integrity post-call (Layer 2 of evidence-integrity.md).
        for ev in evidence_reads:
            self.evidence.reverify(ev)

        stdout_sha = sha256_bytes(stdout_b)
        stderr_sha = sha256_bytes(stderr_b)

        inv = Invocation(
            invocation_id=new_invocation_id(),
            seq=seq,
            case_id=self.case_id,
            tool=self.name,
            args=tuple(argv[1:]),
            stdout_sha256=stdout_sha,
            stderr_sha256=stderr_sha,
            exit_code=exit_code,
            latency_ms=latency_ms,
            started_at=started,
            finished_at=finished,
            evidence_ids_read=tuple(ev.evidence_id for ev in evidence_reads),
        )
        self.invocations.record(inv)

        self.ledger.append(
            "tool_invocation",
            {
                "case_id": self.case_id,
                "invocation_id": inv.invocation_id,
                "seq": inv.seq,
                "tool": inv.tool,
                "args": list(inv.args),
                "exit_code": inv.exit_code,
                "stdout_sha256": inv.stdout_sha256,
                "stderr_sha256": inv.stderr_sha256,
                "latency_ms": inv.latency_ms,
                "started_at": inv.started_at.isoformat(timespec="microseconds"),
                "finished_at": inv.finished_at.isoformat(timespec="microseconds"),
                "evidence_ids_read": list(inv.evidence_ids_read),
            },
        )

        try:
            decoded = stdout_b.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            decoded = stdout_b.decode("latin-1", errors="replace")
        truncated = False
        if len(decoded) > self.stdout_truncate_bytes:
            decoded = decoded[: self.stdout_truncate_bytes]
            truncated = True
        wrapped = wrap_evidence(
            body=decoded,
            tool=self.name,
            invocation_id=inv.invocation_id,
            truncated=truncated,
            bytes_seen=len(stdout_b),
        )

        return ToolExecutionResult(
            invocation=inv,
            stdout_for_llm=wrapped,
            rendered_command=rendered,
        )

    # Convenience for non-async tests / callers.
    def execute_sync(self, args: ToolArgs) -> ToolExecutionResult:
        return asyncio.run(self.execute(args))

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "artifact_family": self.artifact_family,
            "args_schema": self.Args.model_json_schema(),
        }


__all__ = [
    "TypedTool",
    "ToolArgs",
    "ToolExecutionResult",
    "register_tool",
    "iter_tools",
    "get_tool",
]
