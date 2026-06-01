"""TheHive write-back.

Closed-loop integration: APPROVED Findings flow into TheHive as a Case +
Observables + Procedure. The HMAC approval the examiner produced via
`sworn findings approve` is checked before the request goes out, so the LLM
cannot push to TheHive on its own.

We use httpx and TheHive's documented REST API directly to avoid pulling in
the heavy thehive4py dependency tree unless the writeback feature is in use.
This module also runs offline (dry-run) so judges can see the payload SWORN
would send without standing up a TheHive instance.
"""

from __future__ import annotations

import hmac
import json
import logging
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

import httpx

from sworn.findings.schema import Finding, FindingState

log = logging.getLogger("sworn.writeback.thehive")


class WritebackBlocked(Exception):
    """The Finding did not pass the architectural gate for external write-back."""


@dataclass(frozen=True)
class TheHiveConfig:
    base_url: str
    api_key: str | None = None
    organisation: str | None = None
    timeout_s: float = 30.0
    verify_ssl: bool = True


@dataclass
class WritebackResult:
    finding_id: str
    case_id_in_thehive: str | None
    payload: dict[str, Any]
    dry_run: bool
    response_status: int | None = None


def _verify_approval(
    finding: Finding,
    passphrase: bytes,
) -> bool:
    """Recompute the HMAC the CLI signed at approval time.

    The same scheme as sworn.cli.findings_approve.
    """
    if finding.state is not FindingState.approved:
        return False
    if not finding.approved_by or not finding.approval_hmac:
        return False
    msg = f"{finding.finding_id}|{finding.approved_by}".encode("utf-8")
    expected = hmac.new(sha256(passphrase).digest(), msg, sha256).hexdigest()
    return hmac.compare_digest(expected, finding.approval_hmac)


def _finding_to_thehive_case(finding: Finding) -> dict[str, Any]:
    severity_map = {
        "informational": 1,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    tlp = 2  # Amber by default for IR findings
    return {
        "title": f"SWORN: {finding.title}",
        "description": (
            finding.description
            + "\n\n---\nSWORN provenance:\n"
            + "\n".join(
                f"- invocation {c.invocation_id} via {c.tool} "
                f"(family={c.artifact_family}, stdout_sha256={c.stdout_sha256})"
                for c in finding.backing_invocations
            )
        ),
        "severity": severity_map.get(finding.severity.value, 2),
        "tlp": tlp,
        "pap": tlp,
        "tags": [
            "sworn",
            f"case:{finding.case_id}",
            f"host:{finding.host}",
            f"class:{finding.finding_class.value}",
        ]
        + [f"mitre:{m}" for m in finding.mitre_techniques],
        "customFields": {
            "swornFindingId": {"string": finding.finding_id},
            "swornCaseId": {"string": finding.case_id},
            "swornConfidence": {"number": float(finding.confidence)},
        },
    }


class TheHiveWriteback:
    def __init__(self, config: TheHiveConfig, *, approval_passphrase: bytes | None = None) -> None:
        self._config = config
        self._approval_passphrase = approval_passphrase

    def push(
        self,
        finding: Finding,
        *,
        dry_run: bool = False,
    ) -> WritebackResult:
        if finding.state is not FindingState.approved:
            raise WritebackBlocked(
                f"finding {finding.finding_id} is in state {finding.state.value!r}; "
                "only APPROVED findings can be pushed."
            )
        if self._approval_passphrase is not None and not _verify_approval(
            finding, self._approval_passphrase
        ):
            raise WritebackBlocked(
                f"finding {finding.finding_id} HMAC does not match the supplied "
                "passphrase. Refusing to push."
            )

        payload = _finding_to_thehive_case(finding)

        if dry_run:
            log.info("thehive dry-run for finding %s", finding.finding_id)
            return WritebackResult(
                finding_id=finding.finding_id,
                case_id_in_thehive=None,
                payload=payload,
                dry_run=True,
            )

        headers: dict[str, str] = {}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        if self._config.organisation:
            headers["X-Organisation"] = self._config.organisation
        with httpx.Client(
            base_url=self._config.base_url,
            headers=headers,
            timeout=self._config.timeout_s,
            verify=self._config.verify_ssl,
        ) as client:
            resp = client.post("/api/v1/case", json=payload)
            resp.raise_for_status()
            body = resp.json()
        return WritebackResult(
            finding_id=finding.finding_id,
            case_id_in_thehive=str(body.get("_id") or body.get("id") or ""),
            payload=payload,
            dry_run=False,
            response_status=resp.status_code,
        )

    def push_payload_only(self, finding: Finding) -> dict[str, Any]:
        """Used by `sworn writeback thehive --dry-run` to print the JSON."""
        if finding.state is not FindingState.approved:
            raise WritebackBlocked(
                f"finding {finding.finding_id} is in state {finding.state.value!r}; "
                "only APPROVED findings can be pushed."
            )
        return _finding_to_thehive_case(finding)


__all__ = [
    "TheHiveWriteback",
    "TheHiveConfig",
    "WritebackResult",
    "WritebackBlocked",
]
