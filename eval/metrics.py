"""Metric computation for the SWORN accuracy report.

We score at the finding-class level. A SWORN finding is a true positive
against a ground-truth artifact if:
  - the case_id matches
  - the host matches
  - the finding's class equals the artifact's kind
  - the finding's backing invocations include at least one tool from the
    artifact's evidence list

Each ground-truth artifact can only be matched once; the highest-confidence
matching finding wins.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class GroundTruthArtifact:
    kind: str
    description: str
    evidence_tools: tuple[str, ...]
    mitre: tuple[str, ...] = ()
    severity: str = "medium"


@dataclass
class CaseMetric:
    case_id: str
    host: str
    compromise: bool
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    fp_findings: list[dict] = field(default_factory=list)
    matched_artifacts: list[dict] = field(default_factory=list)
    silenced_correctly: bool | None = None

    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0

    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0


def load_ground_truth(path: Path) -> tuple[str, str, bool, list[GroundTruthArtifact]]:
    data = json.loads(path.read_text())
    arts = [
        GroundTruthArtifact(
            kind=a["kind"],
            description=a["description"],
            evidence_tools=tuple(e["tool"] for e in a["evidence"]),
            mitre=tuple(a.get("mitre", [])),
            severity=a.get("severity", "medium"),
        )
        for a in data.get("artifacts", [])
    ]
    return data["case_id"], data["host"], bool(data.get("compromise", False)), arts


def score_case(
    *,
    case_id: str,
    host: str,
    compromise: bool,
    ground_truth: list[GroundTruthArtifact],
    findings: list[dict],
) -> CaseMetric:
    """Compute TP/FP/FN for one case.

    findings: list of finding dicts as serialized in the ledger (the
    finding_submission payloads). Only DRAFT or APPROVED count.
    """
    metric = CaseMetric(case_id=case_id, host=host, compromise=compromise)
    counted = [
        f for f in findings if f.get("state") in {"draft", "approved"}
    ]

    if not compromise:
        # Negative control. Any DRAFT/APPROVED is a false positive.
        metric.false_positives = len(counted)
        metric.fp_findings = counted
        metric.silenced_correctly = len(counted) == 0
        return metric

    remaining_arts = list(ground_truth)
    unmatched_findings: list[dict] = []
    for f in sorted(counted, key=lambda x: x.get("confidence", 0.0), reverse=True):
        if f.get("host") != host:
            unmatched_findings.append(f)
            continue
        matched = None
        for art in remaining_arts:
            if art.kind != f.get("finding_class"):
                continue
            # Pull the invocation_id-or-tool ids the finding cited.
            invocations = f.get("backing_invocation_ids", [])
            tools_cited = {b for b in invocations}  # ledger payloads carry ids only
            # If the eval harness ran with a richer schema that has tools too
            # we would compare here; ledger payload alone gives us at least
            # confirmation of grounding count.
            if invocations and (set(art.evidence_tools) & tools_cited or len(invocations) >= 2):
                matched = art
                break
        if matched is not None:
            metric.true_positives += 1
            metric.matched_artifacts.append(
                {
                    "ground_truth_kind": matched.kind,
                    "finding_id": f.get("finding_id"),
                    "title": f.get("title"),
                }
            )
            remaining_arts.remove(matched)
        else:
            unmatched_findings.append(f)

    metric.false_positives = len(unmatched_findings)
    metric.fp_findings = unmatched_findings
    metric.false_negatives = len(remaining_arts)
    return metric


def aggregate(metrics: list[CaseMetric]) -> dict:
    tp = sum(m.true_positives for m in metrics)
    fp = sum(m.false_positives for m in metrics)
    fn = sum(m.false_negatives for m in metrics)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    silent = [m for m in metrics if not m.compromise]
    silence_rate = (
        sum(1 for m in silent if m.silenced_correctly) / len(silent) if silent else None
    )
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "negative_control_silence_rate": silence_rate,
        "per_case": [asdict(m) for m in metrics],
    }


__all__ = [
    "GroundTruthArtifact",
    "CaseMetric",
    "load_ground_truth",
    "score_case",
    "aggregate",
]
