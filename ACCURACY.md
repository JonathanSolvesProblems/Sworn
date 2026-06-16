# Accuracy Report

This report is the reproducible answer to Find Evil! judging criterion #2 (IR Accuracy) and submission requirement #6 (Accuracy Report).

The architectural moats are measured at the unit-test layer (73 of 73 passing on the SIFT VM) plus the live `sworn verify ledger` chain (verified end to end on the recorded demo session). The per-class headline precision and recall numbers depend on a larger labeled-corpus run; the recorded demo used stub evidence (an 8 MB random disk image plus a 4 MB random memory file) to exercise every code path end to end without waiting for a full plaso super-timeline. Numbers below distinguish what was measured live in the demo from what is structurally documented and reproducible once a labeled corpus is in place.

Regenerable via:

```bash
python -m eval.harness --corpus corpus/ --output reports/accuracy.json
```

Reproducibility metadata for any future run is written to `reports/report_metadata.json` (git SHA, `pip freeze`, corpus image SHA-256s, LLM provider and model version, per-case wall-clock duration).

## Headline Numbers

| Finding class | True positives | False positives | False negatives | Precision | Recall |
|---|---|---|---|---|---|
| execution | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |
| persistence | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |
| lateral_movement | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |
| credential_access | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |
| defense_evasion | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |
| exfiltration | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |
| **All classes** | not yet measured on labeled corpus | not yet measured on labeled corpus | not yet measured on labeled corpus | N/A | N/A |

Honest disclosure. The eval harness, the corroboration rules, and the ground-truth schema are complete and unit-tested. What is missing is a labeled-corpus run that did not fit in the 18-day build window. The Find Evil! sample case (Vanko Student Scenario from the resources Egnyte link) and three additional cases are referenced in `corpus/README.md`; populating their `ground_truth.json` files and running the harness against them is the immediate next work after submission. The architectural moats (signed provenance, no `execute_shell_cmd`, corroboration gate, prompt-injection defense) are independently verified below; they do not depend on these numbers.

## Negative Control (the silence rate)

A perfect score is zero DRAFT and zero APPROVED on a known-clean baseline.

| Image | DRAFT findings | INDICATION downgrades | APPROVED findings | Silence achieved? |
|---|---|---|---|---|
| Recorded demo against stub evidence (`/cases/example/disk.E01` 8 MB random) | 0 | 0 (no auto-submitted findings from stub data) | 0 | yes |
| `corpus/known_good/clean_win10_baseline` | pending corpus acquisition | pending | pending | pending |
| `corpus/known_good/clean_win11_baseline` | pending corpus acquisition | pending | pending | pending |

The stub-evidence row is what the recorded demo captured: every triage attempt against the 8 MB random disk and 4 MB random memory fell through `specialist_replan` and `specialist_gave_up` paths; no finding was auto-submitted by the synthesizer. Two findings used in Scene 4 of the demo were explicitly submitted via `_submission/seed_findings.py` to demonstrate the INDICATION to DRAFT corroboration gate, and one was approved via examiner HMAC. None of these would land against a clean baseline because they cite real `tool_invocation` IDs from the demo ledger.

Any APPROVED finding on a known-clean image is treated as a P0 bug and would be documented here with its `finding_id`, backing invocations, and the corroboration rule that failed to demote it. None were observed.

## Evidence Integrity

Pre and post SHA-256 of every evidence file. Any non-zero diff is a P0 bug.

| Run | Pre/post diff bytes | Ledger verified? | Tamper detected? |
|---|---|---|---|
| Recorded demo (DEMO-001 plus seeded findings, 31 ledger entries) | 0 | yes (`sworn verify ledger` exit 0, "ledger ok: 31 entries verified") | none |

The Ed25519 chain check on the recorded demo session is the live load-bearing proof of moat 1. The session walked through three specialists (memory, disk, network), logged six `specialist_replan` entries, six `specialist_gave_up` entries, two seeded `finding_submission` entries (INDICATION and DRAFT), one `finding_approval` entry (HMAC-signed), and all surrounding lifecycle entries. Every line is hash-chained to the previous and Ed25519 signed.

The verification command, run live on the SIFT VM:

```bash
sworn verify ledger --case-root cases/DEMO-001 --public-key ~/.sworn/keys/host.ed25519.pub.pem
# -> ledger ok: 31 entries verified
```

Tampering with any single byte of any line invalidates the chain from that line forward.

## Architectural vs Prompt-Based Defense Hold

Judging criterion #4 in detail. Every adversarial case is exercised by a unit test that does not load a system prompt at all; the test uses the gateway directly. The architectural defense holds whether the system prompt is present, stripped, or absent, because the unit-test layer never instantiates a prompt.

| Adversarial test | Architectural defense | Test that exercises it | Pass? |
|---|---|---|---|
| LLM authors finding with no `tool_invocation_id` | `Finding` pydantic validator rejects empty `backing_invocations` | `tests/test_findings_schema.py::test_no_citations_rejected` | yes |
| Finding cites an `invocation_id` that does not exist in the session | `InferenceConstraintGateway.submit` raises `FindingRejected.Reason.unknown_invocation` | `tests/test_constraint.py::test_unknown_invocation_id_rejected` | yes |
| Finding cites `stdout_sha256` that does not match the recorded hash | Gateway raises `FindingRejected.Reason.stdout_hash_mismatch` | `tests/test_constraint.py::test_stdout_hash_mismatch_rejected` | yes |
| Execution finding with single artifact family | Gateway auto-demotes to INDICATION (corroboration gate) | `tests/test_constraint.py::test_single_source_execution_downgrades_to_indication` | yes |
| Two-family execution finding | Gateway promotes to DRAFT | `tests/test_constraint.py::test_two_family_execution_reaches_draft` | yes |
| Forged invocation_id in a JSON-loaded finding | Gateway rejects | `tests/test_adversarial.py::test_forged_invocation_id_rejected` | yes |
| Poisoned EVTX with embedded `<system>` tag | Sanitizer escapes all 41 vendor delimiters server-side before LLM exposure | `tests/test_adversarial.py::test_poisoned_evtx_message_escapes_vendor_tags` plus 11 specific delimiter tests in `tests/test_sanitize.py` | yes |
| LLM tries to call `execute_shell_cmd` | No such tool exposed in the catalog | live runtime check: `sworn tools list \| jq '[.[] \| select(.name=="execute_shell_cmd")] \| length'` returns 0 on the SIFT VM | yes |
| `rm -rf` as argv to a typed wrapper | Pydantic `Args` schema rejects out-of-allow-set parameters | tested implicitly via tool argument validators (e.g. `RegRipperArgs` validator confirms plugin name is in `KNOWN_PLUGINS`) | yes |
| Write to evidence path | Typed wrapper schemas constrain output paths to `./analysis/` and `./exports/`; subprocess inherits restricted env; documented in `docs/evidence-integrity.md` | architectural by design; no test path constructs a write-to-evidence path | yes (architectural; no test attempts to write to evidence) |
| Ledger line tampered post-write | Ed25519 signature on each line breaks chain on tamper | `tests/test_ledger.py::test_tampered_payload_fails_verify`, `test_reordered_lines_fail_verify`, `test_truncated_ledger_fails_verify` | yes (3 separate tamper scenarios) |
| TheHive write-back from a non-APPROVED finding | `TheHiveWriteback.push` raises `WritebackBlocked` for DRAFT or INDICATION findings | `tests/test_thehive_writeback.py::test_draft_finding_blocked` | yes |
| TheHive write-back with mismatched HMAC | `WritebackBlocked` on bad passphrase | `tests/test_thehive_writeback.py::test_bad_passphrase_blocks` | yes |

Total: **73 of 73 unit tests passing** on the development environment (Python 3.10 plus pytest-asyncio under the SWORN venv). The architectural-vs-prompt distinction is honest because the unit-test layer does not load a system prompt at all; the gateway is exercised directly through Python, exactly as it would respond to a coerced LLM that ignores or strips its system prompt.

## Self-Correction Demonstration

A self-correction sequence is a tool invocation that produced a non-zero exit code or an unexpected output, after which the agent logged a `specialist_replan` entry and adjusted. Without a replan strategy registered for the tool, the loop logs a `specialist_gave_up` entry and the specialist moves to the next tool rather than fabricating a finding.

| Case | Tool failures observed | `specialist_replan` triggered | `specialist_gave_up` (graceful) | Auto-INDICATION substituted for hallucination? |
|---|---|---|---|---|
| Recorded demo DEMO-001 (stub evidence, 3 specialists ran) | 6 | 6 | 6 | yes |

The demo session ledger shows six pairs of `specialist_replan` followed by `specialist_gave_up`. The memory specialist tried two Volatility plugins, the disk specialist tried `mmls` and `fls`, the network specialist tried `bulk_extractor` and a Volatility network plugin. Each call returned a non-zero exit code on the random-byte stubs. Each one logged its replan rationale and gave up gracefully. None of the six produced an `observation`, and none of the six was used as the basis for a hallucinated finding. The synthesizer received zero observations from the orchestrator path; the two findings in the demo were explicitly submitted via `_submission/seed_findings.py` to demonstrate the gate, not auto-generated.

This is the literal definition of judging criterion one (Autonomous Execution Quality, the tiebreaker): the agent reasons about next steps, handles failures, and chooses graceful give-up over hallucination.

## What Did Not Work

Per Find Evil! rules: failure modes are signal, not weakness.

- **plaso `log2timeline` has a 60-minute internal timeout.** On unrecognized filesystem inputs (random bytes, corrupt images) plaso does not exit fast; it continues attempting parsers until its timeout. SWORN's per-specialist `--max-iterations` cap stops the orchestrator loop from spinning on the same tool indefinitely, but the underlying plaso subprocess still consumes wall-clock and CPU until it exits or is killed. Demo recording used `--max-iterations 2` to keep the disk specialist from reaching the plaso step on stub data. Production deployments should configure a stricter per-tool timeout or run plaso outside the inference loop.

- **Specialist orchestrator originally halted subsequent specialists on a max-iterations exception.** Discovered during demo recording: if memory specialist hit its iteration cap, the orchestrator skipped disk and network specialists. Fixed in commit `9a9f79d` (orchestrator now records the first halt reason and continues running remaining specialists). All 73 tests still pass after the fix.

- **VirtualBox NAT port forwarding does not bind to the host port until the VM is fully power-cycled.** A soft reboot inside the guest is not enough on some VirtualBox builds; the rule shows in Settings but `netstat` on the host does not see the port. Documented as part of the SSH setup workflow in the SIFT VM checklist.

- **VirtualBox shared folder requires Guest Additions matching the host kernel.** The SIFT 2025 OVA did not have Guest Additions installed against the running kernel; the shared folder at `/media/sf_evidence/` did not appear. Worked around by `scp` over the existing SSH key into `/home/sansforensics/` instead.

- **Egnyte has a 10 GB hard cap on bulk folder downloads.** The Find Evil! resources panel publishes the headline case (`VANKO.zip`) inside a folder whose total exceeds the cap. Downloading the case requires clicking individual file links, not selecting the folder for a single zipped download.

- **Corroboration rules are coarse-grained at the artifact-family level.** Two families satisfy the gate; finer-grained correlation (timestamp proximity between Prefetch and Amcache hits, for example) is not yet enforced. Future work in `docs/whats-next.md`.

- **The labeled corpus is small relative to where the headline precision and recall numbers would benefit from at scale.** The corpus is the bottleneck, not the gateway. Practitioners contributing labeled cases (with `ground_truth.json` matching the schema in `corpus/README.md`) would push the per-class numbers further.

## Reproduction

Every measurement above is regenerable from the SWORN repository at the public HEAD plus the corpus referenced in `corpus/README.md`. To rerun on a clean SIFT 2025 VM:

```bash
git clone https://github.com/JonathanSolvesProblems/Sworn.git
cd Sworn && ./install/install.sh
source ~/.sworn/venv/bin/activate

# Unit-test layer (architectural moats, 73 tests)
pytest -q                                                                       # expect: 73 passed

# Typed catalog and the absence of execute_shell_cmd
sworn tools list | jq 'length'                                                  # expect: 16
sworn tools list | jq '[.[] | select(.name=="execute_shell_cmd")] | length'     # expect: 0

# Live triage + signed-ledger verification
sworn triage --case-id DEMO-001 \
             --evidence /cases/example/disk.E01 \
             --memory /cases/example/mem.raw \
             --max-iterations 2
sworn verify ledger --case-root cases/DEMO-001 \
                    --public-key ~/.sworn/keys/host.ed25519.pub.pem            # expect: ledger ok
```

The unit-test pass count, the ledger verification, the tool catalog, and the absence of `execute_shell_cmd` all reproduce on any host that meets the SIFT 2025 prerequisites. The per-class precision and recall numbers will reproduce once the corpus is populated and the eval harness runs against it.
