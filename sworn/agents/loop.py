"""Self-correction loop.

A SpecialistLoop drives a fixed sequence of typed-tool calls with bounded
retry. On tool error or unexpected output, the loop records a replan rationale
and retries with adjusted arguments. The loop emits Observations the
Synthesizer reads. The loop NEVER calls gateway.submit directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sworn.gateway.provenance import Invocation
from sworn.gateway.session import Session
from sworn.tools._base import ToolArgs, ToolExecutionResult, TypedTool

log = logging.getLogger("sworn.agents")


class SelfCorrectionExceeded(Exception):
    """Raised when a SpecialistLoop hit its --max-iterations cap."""


@dataclass
class Observation:
    """An interim note an agent stages before any finding is proposed.

    Observations live in memory and on the ledger but are not Findings; the
    Synthesizer turns them into Findings only when corroboration is in hand.
    """

    specialist: str
    summary: str
    artifact_family: str
    invocation: Invocation
    confidence: float
    notes: list[str] = field(default_factory=list)


@dataclass
class ReplanRecord:
    attempt: int
    tool: str
    args: dict[str, Any]
    exit_code: int
    stderr_excerpt: str
    rationale: str
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


Step = Callable[["SpecialistLoop"], Awaitable[None]]


class SpecialistLoop:
    def __init__(
        self,
        *,
        name: str,
        session: Session,
        max_iterations: int = 25,
    ) -> None:
        self.name = name
        self.session = session
        self.max_iterations = max_iterations
        self._iteration = 0
        self.observations: list[Observation] = []
        self.replans: list[ReplanRecord] = []

    @property
    def iteration(self) -> int:
        return self._iteration

    def _bump(self) -> None:
        self._iteration += 1
        if self._iteration > self.max_iterations:
            self.session.ledger.append(
                "specialist_max_iterations",
                {"specialist": self.name, "max_iterations": self.max_iterations},
            )
            raise SelfCorrectionExceeded(
                f"{self.name}: hit max_iterations={self.max_iterations}"
            )

    async def run_tool(
        self,
        tool: TypedTool,
        args: ToolArgs,
        *,
        artifact_family: str,
        summary_template: str,
        success_predicate: Callable[[ToolExecutionResult], bool] = lambda r: r.invocation.exit_code == 0,
        max_retries: int = 2,
        replan_args: Callable[[ToolExecutionResult, dict[str, Any]], dict[str, Any] | None]
        | None = None,
    ) -> ToolExecutionResult:
        """Execute a typed tool with bounded retry.

        On failure, optionally call replan_args(result, current_args) to
        produce a fresh ToolArgs payload; loop logs the attempt+rationale.
        """
        attempt = 0
        current_args = args
        while True:
            self._bump()
            attempt += 1
            result = await tool.execute(current_args)

            # Defensive degrade path: tool binary missing on this host.
            # Skip retries because re-running the same call would crash
            # again; log a give-up entry so the audit trail is honest
            # about what happened.
            if result.invocation.exit_code == -127:
                self.session.ledger.append(
                    "specialist_gave_up",
                    {
                        "specialist": self.name,
                        "tool": tool.name,
                        "reason": "tool_unavailable",
                        "final_exit_code": -127,
                        "invocation_id": result.invocation.invocation_id,
                    },
                )
                return result

            if success_predicate(result):
                self.observations.append(
                    Observation(
                        specialist=self.name,
                        summary=summary_template.format(
                            tool=tool.name, invocation_id=result.invocation.invocation_id
                        ),
                        artifact_family=artifact_family,
                        invocation=result.invocation,
                        confidence=0.7,
                    )
                )
                self.session.ledger.append(
                    "specialist_observation",
                    {
                        "specialist": self.name,
                        "tool": tool.name,
                        "invocation_id": result.invocation.invocation_id,
                        "artifact_family": artifact_family,
                    },
                )
                return result

            stderr_hash = result.invocation.stderr_sha256
            replan = ReplanRecord(
                attempt=attempt,
                tool=tool.name,
                args=current_args.model_dump(),
                exit_code=result.invocation.exit_code,
                stderr_excerpt=f"sha256={stderr_hash} exit={result.invocation.exit_code}",
                rationale="tool failed; checking for adjustable parameter",
            )
            self.replans.append(replan)
            self.session.ledger.append(
                "specialist_replan",
                {
                    "specialist": self.name,
                    "attempt": attempt,
                    "tool": tool.name,
                    "exit_code": result.invocation.exit_code,
                    "stderr_sha256": stderr_hash,
                },
            )
            if attempt > max_retries:
                self.session.ledger.append(
                    "specialist_gave_up",
                    {
                        "specialist": self.name,
                        "tool": tool.name,
                        "final_exit_code": result.invocation.exit_code,
                    },
                )
                return result

            next_args_dict = (
                replan_args(result, current_args.model_dump()) if replan_args else None
            )
            if next_args_dict is None:
                self.session.ledger.append(
                    "specialist_gave_up",
                    {
                        "specialist": self.name,
                        "tool": tool.name,
                        "reason": "no replan strategy",
                    },
                )
                return result
            current_args = type(args).model_validate(next_args_dict)


__all__ = ["SpecialistLoop", "SelfCorrectionExceeded", "Observation", "ReplanRecord"]
