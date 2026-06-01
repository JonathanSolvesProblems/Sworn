"""CLI tests for the findings subcommands (approve, list, show).

Approval is the architectural separation between the LLM (which drafts) and
the examiner (who signs). These tests assert the HMAC is computed correctly,
the ledger gets a finding_approval entry, and the load helper correctly
flips the state to "approved".
"""

from __future__ import annotations

import getpass
import hmac
import json
from hashlib import sha256
from pathlib import Path

import pytest
from click.testing import CliRunner

from sworn.cli import main as cli_main
from sworn.gateway.ledger import Ledger, load_or_create_signing_key


@pytest.fixture()
def case_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Pin the default key path to this tmp_path so init-keys and approve
    # both land in the same place.
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    key_path = keys_dir / "host.ed25519.pem"
    monkeypatch.setattr("sworn.cli.DEFAULT_KEY", key_path)
    # And ensure cli.findings_approve uses the same default
    case = tmp_path / "cases" / "DEMO-001"
    case.mkdir(parents=True)
    # Seed the ledger with a session_start + a finding_submission so approve
    # has something to anchor against.
    sk = load_or_create_signing_key(key_path)
    ledger = Ledger.open(case / "actions.jsonl", sk)
    ledger.append("session_start", {"case_id": "DEMO-001"})
    ledger.append(
        "finding_submission",
        {
            "case_id": "DEMO-001",
            "finding_id": "f" * 64,
            "host": "DESKTOP-T",
            "finding_class": "execution",
            "state": "draft",
            "backing_invocation_ids": ["id-1", "id-2"],
            "title": "test draft",
            "severity": "high",
            "confidence": 0.9,
            "notes": [],
        },
    )
    return case


def test_findings_list_returns_draft(case_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli_main, ["findings", "list", "--case-root", str(case_root)])
    assert result.exit_code == 0, result.output
    items = json.loads(result.output)
    assert len(items) == 1
    assert items[0]["state"] == "draft"
    assert items[0]["finding_id"] == "f" * 64


def test_findings_show_returns_one(case_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        ["findings", "show", "--case-root", str(case_root), "f" * 64],
    )
    assert result.exit_code == 0, result.output
    item = json.loads(result.output)
    assert item["title"] == "test draft"


def test_findings_show_404_returns_nonzero(case_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        ["findings", "show", "--case-root", str(case_root), "0" * 64],
    )
    assert result.exit_code != 0


def test_findings_approve_writes_hmac_to_ledger(
    case_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # getpass.getpass should return our deterministic passphrase
    monkeypatch.setattr(getpass, "getpass", lambda *_a, **_k: "demo-passphrase")
    runner = CliRunner()
    finding_id = "f" * 64
    result = runner.invoke(
        cli_main,
        [
            "findings",
            "approve",
            "--case-root",
            str(case_root),
            "--examiner",
            "examiner@example.org",
            finding_id,
        ],
    )
    assert result.exit_code == 0, result.output

    # Recompute the expected HMAC the same way cli does.
    msg = f"{finding_id}|examiner@example.org".encode("utf-8")
    expected = hmac.new(sha256(b"demo-passphrase").digest(), msg, sha256).hexdigest()

    raw_lines = (case_root / "actions.jsonl").read_bytes().splitlines()
    approval_entries = [
        json.loads(line) for line in raw_lines if json.loads(line)["kind"] == "finding_approval"
    ]
    assert len(approval_entries) == 1
    payload = approval_entries[0]["payload"]
    assert payload["finding_id"] == finding_id
    assert payload["approved_by"] == "examiner@example.org"
    assert payload["approval_hmac"] == expected


def test_findings_approve_state_visible_in_list(
    case_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda *_a, **_k: "pwd")
    runner = CliRunner()
    finding_id = "f" * 64
    runner.invoke(
        cli_main,
        [
            "findings",
            "approve",
            "--case-root",
            str(case_root),
            "--examiner",
            "examiner@example.org",
            finding_id,
        ],
    )
    result = runner.invoke(cli_main, ["findings", "list", "--case-root", str(case_root)])
    items = json.loads(result.output)
    assert items[0]["state"] == "approved"
    assert items[0]["approved_by"] == "examiner@example.org"
