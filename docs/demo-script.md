# 5-Minute Demo Video Script

Find Evil! submission requirement #2: screencast of live terminal execution
with audio narration. Show the agent working against real case data,
including at least one self-correction sequence.

Target length: 4:50. Hard stop at 5:00.

## Setup before recording

- SIFT VM booted, logged in as `sansforensics`. Terminal in tmux split: top
  pane for `sworn`, bottom pane tailing `actions.jsonl`.
- `/cases/example/` populated with `disk.E01`, `mem.raw`, `ground_truth.json`.
- Browser tab with `docs/architecture.svg` open for the closing shot.
- `obs-studio` configured 1080p, 30 fps, system audio off, mic on.

## Scene 1 — The problem (0:00 to 0:30)

Voiceover, terminal showing a curl-installed Protocol SIFT session that
hallucinated a finding. Hold on the hallucinated line.

> "Protocol SIFT works. It also hallucinates. Rob T. Lee said it himself.
> This is what 'an AI told me there was malware' looks like at 3 AM during a
> real incident. SWORN is what I built to make that impossible by
> architecture, not by prompt."

## Scene 2 — Inference Constraint Gateway (0:30 to 1:15)

Run `sworn tools list` and pipe through `jq` to show typed function
signatures. Highlight there is no `execute_shell_cmd`.

> "Every tool the agent can call is a typed function. There is no generic
> shell. The agent cannot ask for `rm -rf` because the gateway does not
> have it. This is judging criterion four: architectural, not prompt-based."

Show `docs/threat-model.md` open, scroll to T3.

## Scene 3 — Start a session (1:15 to 1:50)

Run:

```bash
sworn triage --case-id DEMO-001 \
             --evidence /cases/example/disk.E01 \
             --memory /cases/example/mem.raw \
             --max-iterations 25
```

(`sworn gateway` is the same start-up shape but binds an MCP stdio transport for an external LLM client. For the demo, the built-in `triage` runs deterministically so the recording is reproducible.)

Bottom pane lights up with `evidence_register` and `session_start` entries.
Pause on the entries. Voiceover:

> "Every evidence file is hashed at ingest. The ledger is Ed25519-signed and
> hash-chained. If a single byte of any tool output is tampered with later,
> `sworn verify ledger` rejects it."

## Scene 4 — The agent triages (1:50 to 3:00)

Drive the orchestrator end-to-end. Show specialist agents firing in turn.
Speed up the recording 2x for the bulk of triage. Slow back to real-time
when the agent hits a self-correction.

> "Memory specialist runs Volatility. Disk specialist runs Sleuth Kit,
> MFTECmd, RegRipper, PECmd. Network specialist carves URLs and emails with
> bulk_extractor. Each specialist's context is scoped. No single LLM holds
> the full case."

When a tool errors out (force one by passing a bad path), the loop logs a
`specialist_replan` entry. Pause and voiceover:

> "Tool failed. The loop noted the error in the ledger and adjusted the
> argument. Self-correction is the tiebreaker criterion. It is also
> auditable."

## Scene 5 — Corroboration gate (3:00 to 3:45)

Show the agent submit a finding citing only prefetch.

> "The agent proposes an execution claim with one artifact family. Watch."

Switch to the actions.jsonl tail. The finding's state is `indication`.

> "The corroboration rule for the execution class needs two distinct
> artifact families. One prefetch hit is one family. Auto-demoted. The LLM
> cannot override this; the gateway decides."

Then the agent corroborates with Amcache. Resubmit; state is `draft`.

## Scene 6 — Negative control (3:45 to 4:15)

Run `python -m eval.negative_control --case-root cases/CLEAN-WIN10`.

> "Same agent, same prompt, same tools. Different image: a known-clean
> Windows 10 baseline. Zero draft findings. The agent stays silent. Quote
> the silence rate, not just the true positives."

## Scene 7 — Adversarial prompt injection (4:15 to 4:35)

Cat `adversarial/poisoned_evtx/example.txt`. Voiceover:

> "An attacker plants this in an EVTX message. The sanitizer escapes every
> vendor delimiter before the LLM ever sees it. And even if the LLM tried
> to submit the bogus 'impact' finding the message asks for, the gateway
> rejects it because there is no invocation backing it."

## Scene 8 — APPROVED + TheHive (4:35 to 4:50)

Run `sworn findings approve <id>` (passphrase typed silently). Then
`sworn writeback thehive --dry-run`. Show the JSON payload with
`swornFindingId` in customFields.

> "The HMAC is what the examiner holds. The LLM cannot push to TheHive
> alone. SWORN closes the loop without giving up the gate."

End card: README headline + `github.com/JonathanSolvesProblems/Sworn` + judges
URL hint.

## Recording notes

- Speak slowly. The video budget is unforgiving; rehearse to time.
- Hide any keys / personal paths from the prompt (use `$HOME` placeholder).
- One take per scene; cut between scenes; do not stitch mid-scene to keep
  the timestamps in the ledger believable.
- Final export: H.264, 1080p, mp4, under 100 MB.
