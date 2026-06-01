"""Session: the in-process bundle of everything one IR case needs.

A Session owns the case_id, the signing key, the evidence registry, the
invocation store, the ledger, and the Inference Constraint Gateway. The MCP
server holds one Session per running case and routes all tool calls and
finding submissions through it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sworn.gateway.constraint import InferenceConstraintGateway
from sworn.gateway.evidence import EvidenceRegistry
from sworn.gateway.ledger import Ledger, load_or_create_signing_key
from sworn.gateway.provenance import InvocationStore


@dataclass
class Session:
    case_id: str
    case_root: Path
    analysis_root: Path
    evidence: EvidenceRegistry
    invocations: InvocationStore
    ledger: Ledger
    gateway: InferenceConstraintGateway
    signing_key: Ed25519PrivateKey

    @classmethod
    def start(
        cls,
        *,
        case_id: str,
        case_root: Path,
        signing_key_path: Path,
    ) -> "Session":
        case_root = case_root.resolve()
        analysis_root = case_root / "analysis"
        analysis_root.mkdir(parents=True, exist_ok=True)
        ledger_path = case_root / "actions.jsonl"

        signing_key = load_or_create_signing_key(signing_key_path)
        ledger = Ledger.open(ledger_path, signing_key)
        ledger.append(
            "session_start",
            {
                "case_id": case_id,
                "case_root": str(case_root),
                "analysis_root": str(analysis_root),
                "sworn_version": __import__("sworn").__version__,
            },
        )

        evidence = EvidenceRegistry()
        invocations = InvocationStore()
        gateway = InferenceConstraintGateway(
            case_id=case_id,
            invocations=invocations,
            evidence=evidence,
            ledger=ledger,
        )
        return cls(
            case_id=case_id,
            case_root=case_root,
            analysis_root=analysis_root,
            evidence=evidence,
            invocations=invocations,
            ledger=ledger,
            gateway=gateway,
            signing_key=signing_key,
        )

    def register_evidence(self, paths: list[Path]) -> list[dict]:
        registered: list[dict] = []
        for p in paths:
            ev = self.evidence.register(p)
            self.ledger.append(
                "evidence_register",
                {
                    "case_id": self.case_id,
                    "evidence_id": ev.evidence_id,
                    "path": str(ev.path),
                    "sha256": ev.sha256,
                    "size_bytes": ev.size_bytes,
                },
            )
            registered.append(
                {
                    "evidence_id": ev.evidence_id,
                    "path": str(ev.path),
                    "sha256": ev.sha256,
                    "size_bytes": ev.size_bytes,
                }
            )
        return registered

    def stop(self) -> None:
        self.ledger.append(
            "session_stop",
            {
                "case_id": self.case_id,
                "invocation_count": len(self.invocations),
            },
        )


__all__ = ["Session"]
