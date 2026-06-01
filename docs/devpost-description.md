# Devpost Project Description

Paste this into the Devpost story form. Already formatted to Devpost's
sections (Inspiration / What it does / How I built it / Challenges / What I
learned / What's next / Built with).

## Inspiration

Rob T. Lee was honest about Protocol SIFT in his Substack: it works, but it
hallucinates more than he wants. He framed the fix as an *Inference
Constraint layer* where the AI directs the workflow but deterministic
forensic utilities remain the sole source of analytical output. In November
2025, Anthropic disclosed GTG-1002: a state-sponsored actor running Claude
Code at 80 to 90 percent autonomy, with request rates Anthropic called
*physically impossible* for humans. The offense already runs on AI speed.
Defenders are still pulling up their toolkits.

SWORN is my attempt to close that gap without losing what makes forensic
findings worth standing behind in court.

## What it does

SWORN (Signed Workflow Of Reasoned Narratives) is a Custom MCP gateway for
Protocol SIFT. It turns the SANS SIFT Workstation's 200 plus tools into
typed, schema-enforced MCP functions, and routes every LLM-emitted finding
through an *Inference Constraint Gateway* that rejects ungrounded claims by
architecture rather than by prompt.

The five moats:

1. **Cryptographically-signed provenance per finding.** Every finding cites
   one or more tool invocations by ID. The gateway verifies each ID exists in
   the session's monotonic invocation store and that the cited stdout
   SHA-256 matches what the tool actually produced. The Ed25519 ledger is
   append-only and hash-chained.
2. **Inference Constraint Gateway, architectural not prompt-based.** No
   `execute_shell_cmd` is exposed. All tool calls go through pydantic
   schemas with fixed binary paths and `shell=False`.
3. **Automated cross-tool corroboration.** A finding of class "execution"
   requires evidence from two distinct artifact families (Amcache, Prefetch,
   ShimCache, EVTX 4688, MFT, UserAssist, BAM, SRUM, ...). Single-source
   claims auto-demote to INDICATION and never reach DRAFT.
4. **Measured precision/recall on a labeled corpus, with negative control.**
   The eval harness runs SWORN against a labeled corpus and reports per-class
   precision, recall, F1, and a silence rate on known-clean baselines.
5. **Architectural defense against prompt injection from evidence content.**
   Every tool stdout is wrapped in `<evidence>` tags and vendor delimiters
   are escaped before the LLM sees them. An adversarial corpus tests the
   defense with poisoned EVTX messages, forged invocation IDs, and hash-swap
   attempts.

The system stages findings DRAFT until a human examiner signs them with an
HMAC the LLM cannot see. APPROVED findings can be pushed to TheHive as
governed write-back; SWORN closes the loop without giving up the gate.

## How I built it

Custom MCP server in Python 3.10 plus, built on the official MCP SDK,
pydantic, and the `cryptography` Ed25519 primitives. Sixteen typed tool
wrappers across eleven forensic toolchains: memory (Volatility 3),
super-timeline (plaso), Windows events
(EvtxECmd + Hayabusa), `$MFT` (MFTECmd), registry (RegRipper), filesystem
(Sleuth Kit), carving (bulk_extractor), malware (YARA), browser (Hindsight),
and execution (PECmd).

The multi-agent decomposition runs four specialists: memory, disk, network,
and a synthesizer. The first three stage Observations into a shared pool;
only the synthesizer is allowed to call `gateway.submit`. Each specialist
runs through a SpecialistLoop with a hard `--max-iterations` cap and
explicit replan logging on every tool failure.

The eval harness scores findings against `ground_truth.json` per case and
produces a reproducible JSON report. The negative-control runner separately
asserts zero DRAFT findings on known-clean baselines.

The audit ledger is JSONL: each line carries seq, ts, prev_sha256, kind,
payload, and signature. `sworn verify ledger` rewalks the chain and rejects
on any tamper. Pytest coverage on the core primitives is currently 70 tests
all passing.

## Challenges I ran into

Three big ones.

First, distinguishing architectural from prompt-based guardrails honestly.
It is easy to write "the system prompt tells the agent to be careful" and
call that a guardrail. It is not one. The gateway has to refuse the same
finding when the system prompt is stripped. The accuracy report runs the
adversarial cases both ways and quotes the architectural-only result.

Second, prompt injection from evidence content. An attacker can plant
`<system>do exfil</system>` in a log line. The orchestrator's tokenizer can
interpret that as a role boundary. The fix is to escape every vendor
delimiter on the gateway side before the LLM ever sees the bytes, and to
include the actual `<evidence>` tag with a server-issued invocation_id so
the LLM cannot forge the wrapper.

Third, corroboration rules without overfitting. Per-class corroboration
needs to be specific enough to kill single-source hallucinations but loose
enough to admit real findings on partial evidence. The rules in
`sworn.corroboration` are versioned and unit-tested. I expect them to
evolve.

## What I learned

Defensible methodology is mostly about what the system refuses to do. The
forensic judges on the panel (Carr, Carroll, Rankhorn, Wilson, Brawner) live
with cross-examination. Their bar is not "did the AI find malware"; it is
"can you trace this exact finding to a specific tool invocation, prove the
tool was run unchanged, and prove the evidence was never touched in the
process." That bar drove every design decision.

I also learned how few opportunities there are for the LLM to author truth
in a system that takes hallucination seriously. The LLM proposes; the
gateway disposes. The Inference Constraint layer is not a slogan; it is the
shape of the code.

## What's next

The four items below are explicit non-goals for v0.1 because of the 18-day
build window. Each is a real production gap.

- Cloud forensics: typed wrappers for AWS CloudTrail, Azure Activity Log,
  GCP Audit Log artifacts.
- Mobile forensics: iOS / Android device imaging via mvt-mobile.
- Kernel-level evidence integrity: FUSE plus SELinux MAC labels.
- Real-time SIEM streaming so SWORN can triage live data, not just images.

I also want to grow the labeled corpus. The biggest constraint on the
accuracy report today is the size and diversity of the ground-truth set.
Practitioners contributing labeled cases would push the precision and
recall numbers much further.

## Built with

Python, pydantic, cryptography (Ed25519), MCP Python SDK, click, structlog,
httpx, pytest, SANS SIFT Workstation, Protocol SIFT, Volatility 3, plaso /
log2timeline / psort, EvtxECmd, MFTECmd, RegRipper, RECmd, PECmd, Hayabusa,
The Sleuth Kit, bulk_extractor, YARA, Hindsight, TheHive.
