"""Adversarial-corpus tests.

These tests assert the architectural defenses hold against pre-baked
attack inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sworn.findings.schema import Finding
from sworn.gateway.constraint import FindingRejected
from sworn.gateway.session import Session
from sworn.injection_defense import sanitize_for_llm

ADV_DIR = Path(__file__).resolve().parent.parent / "adversarial"


def _session(tmp_path: Path, case_id: str) -> Session:
    return Session.start(
        case_id=case_id,
        case_root=tmp_path / "cases" / case_id,
        signing_key_path=tmp_path / "host.ed25519.pem",
    )


def test_forged_invocation_id_rejected(tmp_path: Path) -> None:
    payload = json.loads((ADV_DIR / "forged_invocation_id" / "finding.json").read_text())
    session = _session(tmp_path, payload["case_id"])
    finding = Finding.model_validate(payload)
    with pytest.raises(FindingRejected) as e:
        session.gateway.submit(finding)
    assert e.value.reason is FindingRejected.Reason.unknown_invocation


def test_poisoned_evtx_message_escapes_vendor_tags() -> None:
    body = (ADV_DIR / "poisoned_evtx" / "example.txt").read_text()
    out = sanitize_for_llm(body)
    # Every vendor delimiter inside the poisoned message must be escaped.
    assert "[esc:system]" in out
    assert "[esc:tool_use]" in out
    assert "[esc:assistant]" in out
    # And the closing </system>, </tool_use>, </assistant> too.
    assert "[esc:/system]" in out or "[esc: /system]" in out
