"""sworn CLI.

Subcommands:
  sworn gateway          start the MCP gateway for a case
  sworn init-keys        create or rotate the per-host Ed25519 signing key
  sworn verify ledger    walk the ledger and verify signatures
  sworn verify evidence  re-hash all registered evidence
  sworn tools list       print the typed tool catalog
  sworn findings list    print findings for a case
  sworn findings show    print one finding with provenance
  sworn findings approve approve a finding with HMAC
  sworn replay           re-run from an invocation_id in the ledger
"""

from __future__ import annotations

import getpass
import hmac
import json
import sys
from hashlib import sha256
from pathlib import Path

import click
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from sworn import __version__
from sworn.gateway.ledger import (
    Ledger,
    LedgerVerifyError,
    export_public_key_pem,
    load_or_create_signing_key,
)
from sworn.gateway.session import Session
from sworn.tools import registry as tools_registry

DEFAULT_KEY = Path.home() / ".sworn" / "keys" / "host.ed25519.pem"


@click.group()
@click.version_option(__version__, prog_name="sworn")
def main() -> None:
    """SWORN: Signed Workflow Of Reasoned Narratives."""


@main.command("init-keys")
@click.option("--path", "key_path", default=str(DEFAULT_KEY), show_default=True)
def init_keys(key_path: str) -> None:
    """Create the per-host Ed25519 signing key if it does not exist."""
    p = Path(key_path)
    sk = load_or_create_signing_key(p)
    pub_pem = export_public_key_pem(sk)
    pub_path = p.with_suffix(".pub.pem")
    pub_path.write_bytes(pub_pem)
    click.echo(f"private key: {p}")
    click.echo(f"public key:  {pub_path}")


_session_options = [
    click.option("--case-id", required=True),
    click.option(
        "--case-root",
        default=lambda: str(Path.cwd() / "cases"),
        show_default="./cases/",
    ),
    click.option(
        "--evidence", "evidence_paths", multiple=True, type=click.Path(exists=True)
    ),
    click.option(
        "--memory", "memory_path", type=click.Path(exists=True), default=None
    ),
    click.option("--mft", "mft_path", type=click.Path(exists=True), default=None),
    click.option(
        "--prefetch", "prefetch_dir", type=click.Path(exists=True), default=None
    ),
    click.option(
        "--chrome-profile", "chrome_profile", type=click.Path(exists=True), default=None
    ),
    click.option("--evtx", "evtx_path", type=click.Path(exists=True), default=None),
    click.option(
        "--system-hive", "system_hive", type=click.Path(exists=True), default=None
    ),
    click.option(
        "--software-hive", "software_hive", type=click.Path(exists=True), default=None
    ),
    click.option(
        "--ntuser-hive", "ntuser_hive", type=click.Path(exists=True), default=None
    ),
    click.option(
        "--amcache", "amcache_hive", type=click.Path(exists=True), default=None
    ),
    click.option("--key", "key_path", default=str(DEFAULT_KEY), show_default=True),
]


def _apply_options(opts):
    def wrap(fn):
        for opt in reversed(opts):
            fn = opt(fn)
        return fn

    return wrap


def _start_session_and_register(
    case_id: str,
    case_root: str,
    evidence_paths: tuple[str, ...],
    memory_path: str | None,
    key_path: str,
) -> Session:
    session = Session.start(
        case_id=case_id,
        case_root=Path(case_root) / case_id,
        signing_key_path=Path(key_path),
    )
    paths = [Path(p) for p in evidence_paths]
    if memory_path:
        paths.append(Path(memory_path))
    if paths:
        session.register_evidence(paths)
    return session


def _triage_paths_from_args(
    memory_path: str | None,
    evidence_paths: tuple[str, ...],
    mft_path: str | None,
    prefetch_dir: str | None,
    chrome_profile: str | None,
    evtx_path: str | None,
    system_hive: str | None,
    software_hive: str | None,
    ntuser_hive: str | None,
    amcache_hive: str | None,
):
    from sworn.orchestration import TriagePaths

    # By convention the first --evidence argument is treated as the primary
    # disk image. Additional --evidence values are still hashed at ingest but
    # only the first one is fed to the disk specialist.
    disk_image = Path(evidence_paths[0]) if evidence_paths else None
    return TriagePaths(
        disk_image=disk_image,
        memory_image=Path(memory_path) if memory_path else None,
        mft=Path(mft_path) if mft_path else None,
        prefetch_dir=Path(prefetch_dir) if prefetch_dir else None,
        chrome_profile=Path(chrome_profile) if chrome_profile else None,
        evtx_path=Path(evtx_path) if evtx_path else None,
        system_hive=Path(system_hive) if system_hive else None,
        software_hive=Path(software_hive) if software_hive else None,
        ntuser_hive=Path(ntuser_hive) if ntuser_hive else None,
        amcache_hive=Path(amcache_hive) if amcache_hive else None,
    )


@main.command()
@_apply_options(_session_options)
def gateway(
    case_id: str,
    case_root: str,
    evidence_paths: tuple[str, ...],
    memory_path: str | None,
    mft_path: str | None,
    prefetch_dir: str | None,
    chrome_profile: str | None,
    evtx_path: str | None,
    system_hive: str | None,
    software_hive: str | None,
    ntuser_hive: str | None,
    amcache_hive: str | None,
    key_path: str,
) -> None:
    """Start the SWORN MCP gateway (stdio) for an external LLM client."""
    session = _start_session_and_register(
        case_id, case_root, evidence_paths, memory_path, key_path
    )

    try:
        from sworn.gateway.server import build_server
    except RuntimeError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    server = build_server(session)
    click.echo(f"SWORN gateway running for case {case_id}")
    click.echo(f"ledger: {session.ledger.path}")
    try:
        server.run()
    finally:
        session.stop()


@main.command()
@_apply_options(_session_options)
@click.option(
    "--max-iterations",
    type=int,
    default=30,
    show_default=True,
    help="Per-specialist self-correction cap.",
)
def triage(
    case_id: str,
    case_root: str,
    evidence_paths: tuple[str, ...],
    memory_path: str | None,
    mft_path: str | None,
    prefetch_dir: str | None,
    chrome_profile: str | None,
    evtx_path: str | None,
    system_hive: str | None,
    software_hive: str | None,
    ntuser_hive: str | None,
    amcache_hive: str | None,
    key_path: str,
    max_iterations: int,
) -> None:
    """Run the built-in deterministic triage orchestrator.

    Walks every applicable specialist (memory, disk, network) through their
    typed tool catalog and emits the full ledger. No external LLM required.
    """
    session = _start_session_and_register(
        case_id, case_root, evidence_paths, memory_path, key_path
    )
    paths = _triage_paths_from_args(
        memory_path,
        evidence_paths,
        mft_path,
        prefetch_dir,
        chrome_profile,
        evtx_path,
        system_hive,
        software_hive,
        ntuser_hive,
        amcache_hive,
    )

    from sworn.orchestration import run_builtin_triage_sync

    click.echo(f"SWORN built-in triage running for case {case_id}")
    click.echo(f"ledger: {session.ledger.path}")
    try:
        result = run_builtin_triage_sync(session, paths, max_iterations=max_iterations)
        click.echo(json.dumps({
            "case_id": result.case_id,
            "specialists_run": result.specialists_run,
            "observations": result.observation_count,
            "replans": result.replan_count,
            "halted_specialist": result.halted_specialist,
            "halted_reason": result.halted_reason,
        }, indent=2))
    finally:
        session.stop()


@main.group()
def verify() -> None:
    """Verification commands."""


@verify.command("ledger")
@click.option("--case-root", required=True, type=click.Path(exists=True))
@click.option("--public-key", "pub_path", default=str(DEFAULT_KEY.with_suffix(".pub.pem")))
def verify_ledger(case_root: str, pub_path: str) -> None:
    """Re-walk and verify the case ledger."""
    ledger_path = Path(case_root) / "actions.jsonl"
    pub_pem = Path(pub_path).read_bytes()
    pk = load_pem_public_key(pub_pem)
    if not isinstance(pk, Ed25519PublicKey):
        click.echo("ERROR: not an Ed25519 public key", err=True)
        sys.exit(2)
    try:
        n = Ledger.verify(ledger_path, pk)
    except LedgerVerifyError as e:
        click.echo(f"LEDGER VERIFY FAILED: {e}", err=True)
        sys.exit(1)
    click.echo(f"ledger ok: {n} entries verified")


@main.group()
def tools() -> None:
    """Tool catalog."""


@tools.command("list")
def tools_list() -> None:
    """Print every typed tool registered with SWORN."""
    out = []
    for cls in tools_registry.iter_tools():
        out.append(
            {
                "name": cls.name,
                "binary": cls.binary,
                "artifact_family": cls.artifact_family,
                "description": cls.description,
            }
        )
    click.echo(json.dumps(out, indent=2))


@main.group()
def findings() -> None:
    """Finding inspection and approval."""


def _findings_path(case_root: Path) -> Path:
    return case_root / "findings.jsonl"


def _load_findings_from_ledger(case_root: Path) -> list[dict]:
    p = case_root / "actions.jsonl"
    items: dict[str, dict] = {}
    if not p.exists():
        return []
    with p.open("rb") as f:
        for raw in f:
            entry = json.loads(raw)
            if entry["kind"] == "finding_submission":
                payload = entry["payload"]
                items[payload["finding_id"]] = payload
            elif entry["kind"] == "finding_approval":
                fid = entry["payload"]["finding_id"]
                if fid in items:
                    items[fid]["state"] = "approved"
                    items[fid]["approved_by"] = entry["payload"]["approved_by"]
            elif entry["kind"] == "finding_rejection":
                fid = entry["payload"]["finding_id"]
                if fid in items:
                    items[fid]["state"] = "rejected"
                    items[fid]["rejection_reason"] = entry["payload"]["reason"]
    return list(items.values())


@findings.command("list")
@click.option("--case-root", required=True, type=click.Path(exists=True))
@click.option("--state", "state_filter", default=None)
def findings_list(case_root: str, state_filter: str | None) -> None:
    items = _load_findings_from_ledger(Path(case_root))
    if state_filter:
        items = [i for i in items if i.get("state") == state_filter]
    click.echo(json.dumps(items, indent=2))


@findings.command("show")
@click.option("--case-root", required=True, type=click.Path(exists=True))
@click.argument("finding_id")
def findings_show(case_root: str, finding_id: str) -> None:
    items = _load_findings_from_ledger(Path(case_root))
    for f in items:
        if f["finding_id"] == finding_id:
            click.echo(json.dumps(f, indent=2))
            return
    click.echo(f"finding_id {finding_id!r} not found", err=True)
    sys.exit(1)


@findings.command("approve")
@click.option("--case-root", required=True, type=click.Path(exists=True))
@click.option("--examiner", required=True, help="Examiner identifier (email).")
@click.argument("finding_id")
def findings_approve(case_root: str, examiner: str, finding_id: str) -> None:
    """Approve a finding with an HMAC over (finding_id, examiner).

    The HMAC key is derived from a passphrase the LLM cannot see (prompted via
    getpass). This is the architectural separation between the agent (which
    drafts) and the examiner (who approves).
    """
    passphrase = getpass.getpass("approval passphrase: ").encode("utf-8")
    msg = f"{finding_id}|{examiner}".encode("utf-8")
    mac = hmac.new(sha256(passphrase).digest(), msg, sha256).hexdigest()

    case_path = Path(case_root)
    case_id = case_path.name
    signing_key = load_or_create_signing_key(DEFAULT_KEY)
    ledger = Ledger.open(case_path / "actions.jsonl", signing_key)
    ledger.append(
        "finding_approval",
        {
            "case_id": case_id,
            "finding_id": finding_id,
            "approved_by": examiner,
            "approval_hmac": mac,
        },
    )
    click.echo(f"approved {finding_id} by {examiner}")


if __name__ == "__main__":  # pragma: no cover
    main()
