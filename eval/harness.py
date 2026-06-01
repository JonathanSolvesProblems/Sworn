"""SWORN evaluation harness.

Runs SWORN over a labeled corpus and emits reproducible precision/recall/FP
numbers. The harness does not require a live LLM; it can be driven in two
modes:

  --mode=replay : read findings.jsonl from a previously-recorded case and
                  score against ground_truth.json
  --mode=live   : drive a session end to end (requires Claude + SIFT VM tools)

The replay mode is what `ACCURACY.md` reproduces from. The live mode is what
generates new findings to be replayed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from eval.metrics import aggregate, load_ground_truth, score_case


def _findings_from_ledger(case_root: Path) -> list[dict]:
    ledger_path = case_root / "actions.jsonl"
    if not ledger_path.exists():
        return []
    by_id: dict[str, dict] = {}
    with ledger_path.open("rb") as f:
        for raw in f:
            entry = json.loads(raw)
            payload = entry["payload"]
            kind = entry["kind"]
            if kind == "finding_submission":
                by_id[payload["finding_id"]] = payload
            elif kind == "finding_approval":
                fid = payload["finding_id"]
                if fid in by_id:
                    by_id[fid]["state"] = "approved"
                    by_id[fid]["approved_by"] = payload.get("approved_by")
            elif kind == "finding_rejection":
                fid = payload["finding_id"]
                if fid in by_id:
                    by_id[fid]["state"] = "rejected"
    return list(by_id.values())


def run(corpus_dir: Path, output_path: Path) -> int:
    case_dirs: list[Path] = []
    for sub in ("known_good", "known_bad"):
        root = corpus_dir / sub
        if not root.exists():
            continue
        for c in sorted(root.iterdir()):
            if (c / "ground_truth.json").exists():
                case_dirs.append(c)

    metrics = []
    for case_dir in case_dirs:
        case_id, host, compromise, arts = load_ground_truth(case_dir / "ground_truth.json")
        findings = _findings_from_ledger(case_dir)
        m = score_case(
            case_id=case_id,
            host=host,
            compromise=compromise,
            ground_truth=arts,
            findings=findings,
        )
        metrics.append(m)

    summary = aggregate(metrics)
    summary["report_metadata"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus_dir": str(corpus_dir.resolve()),
        "case_count": len(metrics),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, default=str))
    print(f"wrote {output_path} ({len(metrics)} cases)")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_case"}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="eval.harness")
    ap.add_argument("--corpus", type=Path, default=Path("corpus"))
    ap.add_argument("--output", type=Path, default=Path("reports/accuracy.json"))
    args = ap.parse_args()
    return run(args.corpus, args.output)


if __name__ == "__main__":
    sys.exit(main())
