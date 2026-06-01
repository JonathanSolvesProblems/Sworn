"""Eval metric tests."""

from __future__ import annotations

from eval.metrics import GroundTruthArtifact, aggregate, score_case


def _art(kind: str = "execution", tools: tuple[str, ...] = ("prefetch_pecmd", "registry_regripper")) -> GroundTruthArtifact:
    return GroundTruthArtifact(
        kind=kind,
        description="x",
        evidence_tools=tools,
        mitre=("T1059",),
    )


def test_clean_image_no_findings_is_perfect_silence() -> None:
    m = score_case(
        case_id="C", host="H", compromise=False, ground_truth=[], findings=[]
    )
    assert m.silenced_correctly is True
    assert m.false_positives == 0


def test_clean_image_with_a_draft_is_false_positive() -> None:
    m = score_case(
        case_id="C",
        host="H",
        compromise=False,
        ground_truth=[],
        findings=[
            {
                "case_id": "C",
                "finding_id": "f1",
                "host": "H",
                "finding_class": "execution",
                "state": "draft",
                "backing_invocation_ids": ["a", "b"],
                "confidence": 0.9,
                "title": "bogus",
            }
        ],
    )
    assert m.false_positives == 1
    assert m.silenced_correctly is False


def test_compromised_image_matched_finding_is_true_positive() -> None:
    m = score_case(
        case_id="C",
        host="H",
        compromise=True,
        ground_truth=[_art()],
        findings=[
            {
                "case_id": "C",
                "finding_id": "f1",
                "host": "H",
                "finding_class": "execution",
                "state": "draft",
                "backing_invocation_ids": ["a", "b"],
                "confidence": 0.9,
                "title": "matched",
            }
        ],
    )
    assert m.true_positives == 1
    assert m.false_negatives == 0


def test_compromised_image_missing_finding_is_false_negative() -> None:
    m = score_case(
        case_id="C",
        host="H",
        compromise=True,
        ground_truth=[_art()],
        findings=[],
    )
    assert m.false_negatives == 1
    assert m.true_positives == 0


def test_aggregate_computes_precision_recall_f1() -> None:
    metrics = [
        score_case(
            case_id="C1",
            host="H",
            compromise=True,
            ground_truth=[_art()],
            findings=[
                {
                    "case_id": "C1",
                    "finding_id": "f1",
                    "host": "H",
                    "finding_class": "execution",
                    "state": "draft",
                    "backing_invocation_ids": ["a", "b"],
                    "confidence": 0.9,
                    "title": "t",
                }
            ],
        ),
        score_case(
            case_id="C2",
            host="H",
            compromise=False,
            ground_truth=[],
            findings=[],
        ),
    ]
    agg = aggregate(metrics)
    assert agg["true_positives"] == 1
    assert agg["false_positives"] == 0
    assert agg["false_negatives"] == 0
    assert agg["precision"] == 1.0
    assert agg["recall"] == 1.0
    assert agg["negative_control_silence_rate"] == 1.0
