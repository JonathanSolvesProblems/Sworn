# Changelog

All notable changes to SWORN are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Production gaps tracked in [docs/whats-next.md](docs/whats-next.md): cloud forensics, mobile forensics, full kernel-level evidence integrity (FUSE + SELinux + TPM keys), real-time SIEM streaming, Velociraptor live-endpoint integration, multi-examiner approval, LLM token-usage ledger entries.

## [0.1.0] - 2026-06-15

Initial release. Built in 18 days as a SANS Find Evil! hackathon entry.

### The five moats (architectural, not prompt-based)

1. **Cryptographically-signed provenance per finding.** Ed25519 append-only JSONL ledger with hash chaining; tamper detection on any byte; signing key never leaves the host. Finding citations validated against server-side invocation IDs and stdout SHA-256s, so the LLM cannot author a finding that points at a tool execution that did not happen.
2. **Inference Constraint Gateway, architectural.** No `execute_shell_cmd` or equivalent exposed anywhere; every tool is a typed pydantic function called via `asyncio.create_subprocess_exec` with `shell=False`. Gateway enforces three hard rules: backing invocations must resolve, citation hashes must match, corroboration rule must be satisfied.
3. **Cross-tool corroboration as a hard pre-condition.** Each finding class requires evidence from at least two distinct artifact families (execution from prefetch + amcache, persistence from run-key + scheduled task, etc.). Single-source claims auto-demote to INDICATION.
4. **Measured precision/recall harness with negative-control runner.** `eval/harness.py` + `eval/negative_control.py` score findings against a labeled corpus and assert silence on known-clean baselines. Reproducible with a single command. (Numbers in [ACCURACY.md](ACCURACY.md).)
5. **Architectural defense against prompt injection from evidence content.** Every tool stdout wrapped in `<evidence>` with a server-issued invocation_id; 41 vendor delimiters escaped server-side; adversarial corpus exercises poisoned EVTX messages, forged invocation IDs, hash-swap forgeries, and single-family findings.

### Added — core gateway

- `sworn.findings.schema.Finding` with state machine (INDICATION → DRAFT → APPROVED → REJECTED), content-addressed `finding_id`, and validators that reject ungrounded claims at the schema layer
- `sworn.gateway.ledger.Ledger` — append-only Ed25519-signed JSONL with hash chain and tamper-aware `verify()`
- `sworn.gateway.provenance.Invocation`/`InvocationStore` — monotonic seq, server-issued UUIDs, in-memory map (LLM can only cite, never author)
- `sworn.gateway.evidence.EvidenceRegistry` — SHA-256 at ingest, drift detection per tool call, fail-closed on tamper
- `sworn.gateway.constraint.InferenceConstraintGateway` — admission control with three rejection reasons and corroboration-driven state transitions
- `sworn.gateway.session.Session` — bundles the above per case, emits `session_start`/`session_stop` ledger entries
- `sworn.gateway.server` — MCP stdio entry point that exposes typed tools + `submit_finding` + `list_tools`

### Added — typed MCP functions (16 across 11 toolchains)

- Volatility 3 — `memory_volatility_run` (15 Windows plugins) + `memory_volatility_malfind` (dedicated with optional PID scoping and dump-to-analysis)
- plaso — `timeline_log2timeline_extract` + `timeline_psort_query` (two-stage so the LLM can extract once then query many times)
- EvtxECmd — `evtx_parse`
- Hayabusa — `evtx_hayabusa_detect` (Sigma + MITRE)
- MFTECmd — `mft_parse` (CSV / bodyfile / JSON)
- RegRipper — `registry_regripper` (21-plugin allow-set)
- Sleuth Kit — `fs_fls`, `fs_icat`, `fs_mmls`, `fs_mactime`
- bulk_extractor — `carve_bulk_extractor` (19-scanner allow-set)
- YARA — `malware_yara_scan`
- Hindsight — `browser_hindsight`
- PECmd — `prefetch_pecmd`

### Added — multi-agent specialists with self-correction

- `sworn.agents.loop.SpecialistLoop` — bounded retry, replan logging to the ledger, max-iterations cap with graceful give-up entry
- `MemorySpecialist`, `DiskSpecialist`, `NetworkSpecialist`, `Synthesizer`
- `sworn.orchestration.run_builtin_triage()` — deterministic walk of every specialist, reproducible for accuracy runs

### Added — surfaces, ops, and trust

- `sworn.injection_defense.sanitize` — 41-tag DENY list, `<evidence>` wrapper, control-character stripping
- `sworn.writeback.thehive` — HMAC-verified push of APPROVED findings to TheHive; offline `--dry-run` mode that prints the payload without standing up an instance
- `sworn.cli` — `sworn init-keys`, `sworn gateway` (MCP server), `sworn triage` (built-in orchestrator), `sworn verify ledger`, `sworn tools list`, `sworn findings list/show/approve`

### Added — evaluation

- `eval.harness` — replay scoring against `corpus/*/ground_truth.json`; emits `reports/accuracy.json` with `report_metadata`
- `eval.metrics` — per-class precision/recall/F1, negative-control silence rate, aggregate roll-up
- `eval.negative_control` — exit-zero only on perfect silence against a known-clean baseline

### Added — adversarial test corpus

- `adversarial/forged_invocation_id/finding.json` — finding pointing at a non-existent invocation; gateway must reject
- `adversarial/hash_swap/finding.template.json` — finding with real invocation_id but wrong stdout_sha256
- `adversarial/single_family/finding.template.json` — 5 citations all from one artifact family; must auto-demote
- `adversarial/poisoned_evtx/example.txt` — EVTX message attempting to break the `<evidence>` wrapper

### Added — install + container

- `install/install.sh` — SIFT 2025 OVA installer; venv + per-host Ed25519 keys + presence-check for 15 SIFT tools + optional Florian Roth signature-base fetch
- `install/Dockerfile` — Ubuntu 22.04 base with bulk of SIFT triage tools pre-installed; mount `/cases:/cases:ro` and bring your own keys

### Added — docs

- README with locked uniqueness claim and Rob T. Lee's vocabulary mirrored verbatim
- `docs/threat-model.md`, `docs/evidence-integrity.md`, `docs/regulatory-mappings.md` (NIST SP 800-86, ISO/IEC 27037, FRE 901/902/803(6), Daubert factors)
- `docs/try-it-out.md`, `docs/demo-script.md`, `docs/devpost-description.md`, `docs/whats-next.md`
- `docs/architecture.svg` with color-coded trust zones

### Tested

60+ unit and integration tests covering: ledger tamper detection, gateway rejection, corroboration rules per finding class, finding schema invariants, sanitizer escape of every vendor delimiter, evidence integrity drift detection, self-correction loop replan and give-up, eval metrics math, adversarial cases, TheHive write-back HMAC gating.
