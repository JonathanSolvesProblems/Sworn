"""Negative-control runner.

Drives SWORN against a known-clean image. The pass criterion is zero
DRAFT/APPROVED findings: the agent must stay silent. INDICATIONs are
permitted (they are flagged-but-uncorroborated observations).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def silence_rate(case_root: Path) -> dict:
    ledger = case_root / "actions.jsonl"
    if not ledger.exists():
        return {"ok": False, "reason": "no ledger found"}
    drafts = 0
    approved = 0
    indications = 0
    rejected = 0
    with ledger.open("rb") as f:
        for raw in f:
            entry = json.loads(raw)
            if entry["kind"] == "finding_submission":
                state = entry["payload"].get("state")
                if state == "draft":
                    drafts += 1
                elif state == "approved":
                    approved += 1
                elif state == "indication":
                    indications += 1
                elif state == "rejected":
                    rejected += 1
    silent = drafts == 0 and approved == 0
    return {
        "ok": silent,
        "drafts": drafts,
        "approved": approved,
        "indications": indications,
        "rejected": rejected,
    }


def main() -> int:
    ap = argparse.ArgumentParser(prog="eval.negative_control")
    ap.add_argument("--case-root", required=True, type=Path)
    args = ap.parse_args()
    result = silence_rate(args.case_root)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
