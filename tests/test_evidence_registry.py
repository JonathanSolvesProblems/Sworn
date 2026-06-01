"""EvidenceRegistry integrity tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from sworn.gateway.evidence import EvidenceIntegrityViolation, EvidenceRegistry


def test_register_and_reverify_clean(tmp_path: Path) -> None:
    p = tmp_path / "disk.E01"
    p.write_bytes(b"clean evidence bytes")
    reg = EvidenceRegistry()
    ev = reg.register(p)
    assert ev.size_bytes == len(b"clean evidence bytes")
    reg.reverify(ev)  # must not raise


def test_reverify_detects_tamper(tmp_path: Path) -> None:
    p = tmp_path / "disk.E01"
    p.write_bytes(b"original")
    reg = EvidenceRegistry()
    ev = reg.register(p)
    p.write_bytes(b"tampered")
    with pytest.raises(EvidenceIntegrityViolation):
        reg.reverify(ev)


def test_registering_same_path_twice_returns_same_id(tmp_path: Path) -> None:
    p = tmp_path / "mem.raw"
    p.write_bytes(b"x" * 1024)
    reg = EvidenceRegistry()
    a = reg.register(p)
    b = reg.register(p)
    assert a.evidence_id == b.evidence_id


def test_get_by_path_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "mem.raw"
    p.write_bytes(b"y" * 1024)
    reg = EvidenceRegistry()
    ev = reg.register(p)
    again = reg.get_by_path(p)
    assert again is not None
    assert again.evidence_id == ev.evidence_id


def test_register_missing_path_errors(tmp_path: Path) -> None:
    reg = EvidenceRegistry()
    with pytest.raises(FileNotFoundError):
        reg.register(tmp_path / "does-not-exist.bin")
