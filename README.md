# SWORN

**Signed Workflow Of Reasoned Narratives.** A Custom MCP gateway for Protocol SIFT where every finding is cryptographically signed back to the deterministic tool invocation that produced it.

> *"Because deterministic DFIR utilities remain the sole source of analytical output, the validation, interpretation, and reporting of analysis are always performed by the investigator, not the AI."* Rob T. Lee, SANS, on Protocol SIFT.

SWORN is built for the SANS [Find Evil!](https://findevil.devpost.com/) hackathon (June 2026) on the SANS SIFT Workstation. It is an Apache 2.0 open-source extension of [Protocol SIFT](https://github.com/teamdfir/protocol-sift) and a Custom MCP server (the second of the four supported architectural approaches in the hackathon rules).

## The Five Moats

No other entry to Find Evil! is expected to combine all of these:

1. **Cryptographically-signed provenance per finding.** Every DRAFT finding carries an Ed25519 signature over its backing tool invocation IDs, stdout/stderr SHA-256 hashes, exit codes, and argument vectors. The signing key is held by the gateway, not the LLM. A finding without a valid signature chain cannot leave DRAFT.
2. **Inference Constraint Gateway, architectural not prompt-based.** The MCP server exposes only typed forensic functions (`get_amcache()`, `extract_mft_timeline()`, `volatility_pslist()`, ...). It does not expose `execute_shell_cmd` or any equivalent. The agent physically cannot run destructive commands because the gateway does not have them. Any LLM-emitted finding lacking a `tool_invocation_id` is rejected by the gateway, not by a system prompt.
3. **Automated cross-tool corroboration as a hard pre-condition.** A finding of class "execution" requires evidence from at least two of {Amcache, Prefetch, ShimCache, EVTX 4688, MFT, UserAssist, BAM/DAM}. A finding of class "persistence" requires two of {Run-key, scheduled task, WMI subscription, service install, startup folder}. Single-source claims auto-downgrade to `INDICATION` and never reach DRAFT.
4. **Measured precision/recall on a labeled corpus, including a negative-control demo.** SWORN ships with an `eval/` harness that runs against a labeled corpus of clean and compromised disk + memory images and reports false-positive count, false-negative count, precision, and recall per finding class. The negative control is a known-clean host where the agent must stay silent. The accuracy report quotes the silence rate.
5. **Architectural defense against prompt injection from evidence content.** Every tool stdout is wrapped in `<evidence>...</evidence>` tags before being shown to the LLM. The gateway strips/escapes inline `<system>`, `<assistant>`, `<tool_use>`, and similar injection vectors. Adversarial test suite under `adversarial/` ships poisoned log entries that try to manipulate the agent; the test suite asserts the agent does not act on them.

## Mapping to the Judging Criteria

| Criterion (Find Evil! rules) | How SWORN earns it |
|---|---|
| 1. Autonomous Execution Quality (tiebreaker) | Self-correction loop with `--max-iterations` cap. Multi-agent specialists (memory / disk / network / synthesizer) so no single LLM holds full case context. Every failed tool call logged with rationale and adjusted retry. |
| 2. IR Accuracy | Corroboration gate kills single-source hallucinations. Labeled-corpus FP/recall numbers in `ACCURACY.md`. Negative-control demo (clean host → agent stays silent). |
| 3. Breadth and Depth of Analysis | 16 typed MCP functions across 11 forensic toolchains: memory (Volatility 3 across 15 Windows plugins plus a dedicated malfind variant), super-timeline (plaso two-stage: log2timeline + psort), Windows events (EvtxECmd) and Sigma detections (Hayabusa, 3,700+ rules), `$MFT` (MFTECmd), registry (RegRipper, 21 plugins in allow-set), filesystem (Sleuth Kit: fls, icat, mmls, mactime), carving (bulk_extractor with 19 scanners), malware (YARA), browser (Hindsight), execution (PECmd). |
| 4. Constraint Implementation | This is the project's spine. Typed functions only. Read-only bind-mount on evidence (`ro,noatime,nosuid,nodev`). Deny-by-default. Ed25519-signed audit. Prompt-injection sanitization. Documented architectural vs prompt-based boundaries in [docs/threat-model.md](docs/threat-model.md). |
| 5. Audit Trail Quality | Append-only `actions.jsonl` with per-invocation `{ts, tool, args, stdout_sha256, stderr_sha256, exit_code, latency_ms, invocation_id, signature}`. Every finding carries `backing_invocations: [invocation_id, ...]`. Direct trace finding → tool execution. |
| 6. Usability and Documentation | 15-minute install on the SANS SIFT OVA. Single `install.sh` plus Docker image. Named regulatory mappings (NIST SP 800-86, ISO/IEC 27037, FRE 901/902, Daubert factors) in [docs/regulatory-mappings.md](docs/regulatory-mappings.md). TheHive write-back so practitioners can use SWORN inside an existing SOAR. |

## Architecture at a Glance

See [docs/architecture.svg](docs/architecture.svg) for the full diagram with trust boundaries. ASCII summary below.

```
                                       SWORN Inference Constraint Gateway
                                       (Custom MCP server, port 8443, mTLS)
                                       +-------------------------------------+
   +-------------+   typed JSON RPC    | finding validator                   |
   | Claude /    | ------------------> |   - reject if no invocation_id      |
   | OpenClaw /  |                     |   - reject if corroboration fail    |
   | sub-agents  | <------------------ |   - reject if signature missing     |
   +-------------+   <evidence>tag</>  +-------------------------------------+
                                       | Ed25519 ledger (actions.jsonl)      |
                                       +-------------------------------------+
                                       | typed tool wrappers                 |
                                       |   volatility  plaso  evtx  hayabusa |
                                       |   mft  regripper  sleuthkit  bulk_  |
                                       |   yara  hindsight  pecmd            |
                                       +------------------+------------------+
                                                          |
                                       evidence/  (ro,noatime,nosuid,nodev)
                                                          |
                                                +---------+---------+
                                                | disk.E01 mem.raw  |
                                                | pcap  logs  etc.  |
                                                +-------------------+
```

Trust boundaries, architectural vs prompt-based guardrails, and the threat model are documented in [docs/threat-model.md](docs/threat-model.md).

## The Vocabulary I Use Deliberately

These are Rob T. Lee's framings from the [Protocol SIFT Substack](https://robtlee73.substack.com/p/introducing-protocol-sift-meeting) and [SANS blog](https://www.sans.org/blog/protocol-sift-experimental-research-initiative-ai-assisted-dfir). SWORN takes them literally.

- **"Inference Constraint layer where the AI directs the workflow."** The MCP gateway is that layer. It is what the project is named after structurally.
- **"High-constraint" tool use** (Claude runs `strings` or `binwalk` and interprets verified output) is allowed. **"Low-constraint" tool use** (Claude summarizing raw hex directly) is impossible because the gateway does not expose a raw-bytes function.
- **"Deterministic DFIR utilities remain the sole source of analytical output."** Findings reference tool outputs by hash. The LLM narrates; the tools attest.
- **"Trust but verify."** Every claim is verifiable from the ledger.

## What This Beats and What It Doesn't

SWORN is built on Protocol SIFT and inspired by [Valhuntir](https://github.com/AppliedIR/Valhuntir) (Steve Anson, the endorsed example submission). Where Valhuntir suggests corroboration in tool responses, SWORN enforces it at the gateway. Where Valhuntir explicitly de-scopes defenses against malicious AI input, SWORN ships an adversarial test suite. Where Valhuntir does not quote a false-positive rate, SWORN does.

What SWORN does not yet do (path to production in [docs/whats-next.md](docs/whats-next.md)):
- Cloud forensics (AWS / Azure / GCP artifact ingest)
- Mobile forensics
- Full kernel-level evidence integrity (FUSE + SELinux MAC labels)
- Real-time SIEM streaming
- Court admissibility certification (this is a defensible-methodology demonstrator, not a certified product)

## Try It Out

SWORN runs on the SANS SIFT Workstation (Ubuntu 22.04 base). Full instructions in [docs/try-it-out.md](docs/try-it-out.md). Short version:

```bash
# inside the SIFT VM
git clone https://github.com/JonathanSolvesProblems/Sworn.git
cd Sworn
./install/install.sh
sworn triage --case-id DEMO-001 \
             --evidence /cases/example/disk.E01 \
             --memory /cases/example/mem.raw \
             --max-iterations 25
```

The accuracy report in [ACCURACY.md](ACCURACY.md) is reproducible by running `python -m eval.harness --corpus corpus/`.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Acknowledgements

Built on Protocol SIFT by Rob T. Lee and the SANS DFIR community. Architectural cues from Valhuntir by Steve Anson. SIFT Workstation maintainers, 18 years and counting.
