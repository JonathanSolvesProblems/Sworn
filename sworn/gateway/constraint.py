"""Inference Constraint Gateway.

Rob T. Lee's "Inference Constraint layer where the AI directs the workflow."
This module is what makes SWORN refuse to relay an LLM-authored finding that
is not grounded in a deterministic tool invocation.

The gateway runs in-process beside the MCP server and is consulted on every
finding submission. It is the load-bearing defense for moats #1 and #3.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

from sworn.corroboration import gated_state
from sworn.findings.schema import Finding, FindingState
from sworn.gateway.evidence import EvidenceRegistry
from sworn.gateway.ledger import Ledger
from sworn.gateway.provenance import InvocationStore


class FindingRejected(Exception):
    """The gateway refused to admit a finding."""

    class Reason(str, enum.Enum):
        no_provenance = "no_provenance"
        unknown_invocation = "unknown_invocation"
        stdout_hash_mismatch = "stdout_hash_mismatch"
        artifact_family_mismatch = "artifact_family_mismatch"
        schema_invalid = "schema_invalid"

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass
class FindingAdmissionResult:
    finding: Finding
    state: FindingState
    notes: list[str]


class InferenceConstraintGateway:
    def __init__(
        self,
        *,
        case_id: str,
        invocations: InvocationStore,
        evidence: EvidenceRegistry,
        ledger: Ledger,
    ) -> None:
        self._case_id = case_id
        self._invocations = invocations
        self._evidence = evidence
        self._ledger = ledger

    def submit(self, finding: Finding) -> FindingAdmissionResult:
        if finding.case_id != self._case_id:
            raise FindingRejected(
                FindingRejected.Reason.schema_invalid,
                f"finding.case_id ({finding.case_id}) does not match session "
                f"({self._case_id})",
            )

        notes: list[str] = []

        # Moat #1:provenance is required and must resolve.
        if not finding.backing_invocations:
            raise FindingRejected(
                FindingRejected.Reason.no_provenance,
                "Finding has no backing invocations.",
            )
        for citation in finding.backing_invocations:
            inv = self._invocations.get(citation.invocation_id)
            if inv is None:
                raise FindingRejected(
                    FindingRejected.Reason.unknown_invocation,
                    f"invocation_id {citation.invocation_id} not in this session",
                )
            if inv.tool != citation.tool:
                raise FindingRejected(
                    FindingRejected.Reason.schema_invalid,
                    f"citation tool {citation.tool!r} does not match invocation "
                    f"tool {inv.tool!r}",
                )
            if inv.stdout_sha256 != citation.stdout_sha256:
                raise FindingRejected(
                    FindingRejected.Reason.stdout_hash_mismatch,
                    f"invocation {inv.invocation_id} stdout hash drift",
                )

        # Moat #3:corroboration gate decides DRAFT vs INDICATION.
        state = gated_state(finding)
        if state is FindingState.indication:
            notes.append(
                "Corroboration rule for class "
                f"{finding.finding_class.value!r} not satisfied; "
                "downgraded to INDICATION."
            )
        admitted = finding.model_copy(update={"state": state})

        # Audit.
        self._ledger.append(
            "finding_submission",
            {
                "case_id": self._case_id,
                "finding_id": admitted.finding_id,
                "host": admitted.host,
                "finding_class": admitted.finding_class.value,
                "state": admitted.state.value,
                "title": admitted.title,
                "severity": admitted.severity.value,
                "backing_invocation_ids": [
                    c.invocation_id for c in admitted.backing_invocations
                ],
                "confidence": admitted.confidence,
                "notes": notes,
            },
        )

        return FindingAdmissionResult(finding=admitted, state=admitted.state, notes=notes)

    def approve(
        self, *, finding_id: str, approved_by: str, approval_hmac: str
    ) -> dict[str, Any]:
        """Examiner approval transition. The HMAC is supplied by `sworn findings
        approve`, not by the LLM.
        """
        self._ledger.append(
            "finding_approval",
            {
                "case_id": self._case_id,
                "finding_id": finding_id,
                "approved_by": approved_by,
                "approval_hmac": approval_hmac,
            },
        )
        return {"finding_id": finding_id, "state": FindingState.approved.value}

    def reject(self, *, finding_id: str, reason: str, by: str) -> dict[str, Any]:
        self._ledger.append(
            "finding_rejection",
            {
                "case_id": self._case_id,
                "finding_id": finding_id,
                "reason": reason,
                "by": by,
            },
        )
        return {"finding_id": finding_id, "state": FindingState.rejected.value}


__all__ = ["InferenceConstraintGateway", "FindingRejected", "FindingAdmissionResult"]
