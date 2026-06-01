"""Finding schema.

A Finding is the unit of truth SWORN produces. It is what gets written back to
TheHive, what an examiner approves, and what (if SWORN ever earns it) testifies
in court. Therefore:

  - A Finding cannot exist without at least one backing tool invocation.
  - A Finding's state machine is enforced by the gateway, not by the LLM.
  - Findings are content-addressed so re-ingestion never produces duplicates.
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator


class FindingClass(str, enum.Enum):
    """MITRE-ATT&CK-aligned high-level finding classes.

    Each class has a corroboration rule registered in sworn.corroboration. The
    gateway uses the class to decide which artifact families must be present
    before a finding can leave INDICATION and reach DRAFT.
    """

    execution = "execution"
    persistence = "persistence"
    privilege_escalation = "privilege_escalation"
    defense_evasion = "defense_evasion"
    credential_access = "credential_access"
    discovery = "discovery"
    lateral_movement = "lateral_movement"
    collection = "collection"
    command_and_control = "command_and_control"
    exfiltration = "exfiltration"
    impact = "impact"


class FindingState(str, enum.Enum):
    """State machine for a Finding.

      INDICATION -> DRAFT -> APPROVED
              \\---> REJECTED
    """

    indication = "indication"
    draft = "draft"
    approved = "approved"
    rejected = "rejected"


class Severity(str, enum.Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EvidenceCitation(BaseModel):
    """A pointer from a Finding back to a specific tool invocation.

    The gateway verifies the cited invocation exists in the current session
    and that the cited stdout_sha256 matches what the tool actually produced.
    The LLM does not get to author these fields freely; it must pass the
    invocation_id it was handed when the tool returned.
    """

    invocation_id: Annotated[str, StringConstraints(min_length=36, max_length=36)]
    tool: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    artifact_family: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    stdout_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    excerpt: Annotated[str, StringConstraints(max_length=2048)] = ""


class Finding(BaseModel):
    """A claim about evidence, with provenance.

    A Finding must cite at least one EvidenceCitation. The gateway enforces:
      - Every cited invocation_id exists in the session's invocation map.
      - Every cited stdout_sha256 matches the recorded hash.
      - The finding_class's corroboration rule is satisfied (otherwise the
        gateway downgrades state to INDICATION).
    """

    finding_id: Annotated[str, StringConstraints(min_length=64, max_length=64)] = ""
    case_id: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    host: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    finding_class: FindingClass
    severity: Severity
    title: Annotated[str, StringConstraints(min_length=4, max_length=200)]
    description: Annotated[str, StringConstraints(min_length=8, max_length=8000)]
    mitre_techniques: list[Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]] = (
        Field(default_factory=list)
    )
    backing_invocations: list[EvidenceCitation] = Field(default_factory=list, min_length=1)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    state: FindingState = FindingState.indication
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: str | None = None
    approval_hmac: str | None = None
    rejection_reason: str | None = None

    model_config = {"extra": "forbid"}

    @field_validator("backing_invocations")
    @classmethod
    def _at_least_one_citation(cls, v: list[EvidenceCitation]) -> list[EvidenceCitation]:
        if not v:
            raise ValueError(
                "A Finding must cite at least one EvidenceCitation. "
                "The Inference Constraint Gateway rejects ungrounded claims."
            )
        return v

    @model_validator(mode="after")
    def _compute_finding_id(self) -> Finding:
        if not self.finding_id:
            payload = {
                "case_id": self.case_id,
                "host": self.host,
                "finding_class": self.finding_class.value,
                "title": self.title,
                "backing_invocations": sorted(
                    (c.invocation_id for c in self.backing_invocations)
                ),
            }
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            object.__setattr__(self, "finding_id", digest)
        return self

    @model_validator(mode="after")
    def _approval_invariants(self) -> Finding:
        if self.state is FindingState.approved:
            if not self.approved_by or not self.approval_hmac:
                raise ValueError(
                    "APPROVED state requires approved_by and approval_hmac. "
                    "The LLM cannot supply these; the examiner does."
                )
        if self.state is FindingState.rejected and not self.rejection_reason:
            raise ValueError("REJECTED state requires a rejection_reason.")
        return self

    def artifact_families(self) -> set[str]:
        """Distinct artifact families backing this finding (used by corroboration)."""
        return {c.artifact_family for c in self.backing_invocations}
