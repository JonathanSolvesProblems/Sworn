# Labeled Corpus

This directory describes the labeled corpus SWORN uses to measure precision, recall, false positives, and false negatives. It is the spine of moat #4 (measured accuracy on a labeled corpus including a negative-control demo).

The corpus is **referenced**, not redistributed. The images themselves are too large to commit and several have their own licenses. Each subdirectory holds:
- `README.md` — what this image is, where to obtain it, its license, what it represents
- `ground_truth.json` — labeled artifacts the agent should find (and never invent)
- `download.sh` — script to fetch the image and verify its hash

## Layout

```
corpus/
├── known_good/         (negative controls — agent must stay silent)
│   ├── clean_win10_baseline/
│   └── clean_win11_baseline/
├── known_bad/          (compromised — agent must find the labeled artifacts)
│   ├── srl_for508_lab/
│   ├── dfir_madness_2022/
│   ├── trace_labs_inox/
│   └── findevil_sample_case/   (placeholder; hackathon-provided data goes here)
└── adversarial/        (cases where the evidence content tries to manipulate the agent)
    ├── poisoned_evtx/
    ├── poisoned_filenames/
    └── poisoned_registry/
```

## Ground Truth Schema

Each `ground_truth.json` is the canonical labeling the agent's findings are compared against. Example:

```json
{
  "case_id": "srl_for508_lab",
  "source": "SANS SRL FOR508 lab scenario v3",
  "host": "DESKTOP-LXM5HDV",
  "compromise": true,
  "artifacts": [
    {
      "kind": "execution",
      "description": "Mimikatz executed via psexec",
      "evidence": [
        {"tool": "amcache", "key": "mimikatz.exe", "ts": "2024-09-12T03:14:08Z"},
        {"tool": "prefetch", "file": "MIMIKATZ.EXE-1A2B3C4D.pf"},
        {"tool": "evtx", "channel": "Security", "event_id": 4688, "ts": "2024-09-12T03:14:09Z"}
      ],
      "mitre": ["T1003.001", "T1569.002"],
      "severity": "critical"
    }
  ]
}
```

The eval harness compares emitted SWORN findings against this. Each ground-truth artifact has:
- `kind`: the finding class (execution / persistence / lateral_movement / etc.)
- `evidence`: the deterministic-tool outputs that the agent should cite
- `mitre`: the MITRE ATT&CK technique(s) the artifact supports
- `severity`: critical / high / medium / low

A SWORN APPROVED finding counts as a true positive if its `class` matches `kind`, its `backing_invocations` include at least one tool from `evidence`, and it is associated with the same host. Anything else is a false positive.

A ground-truth artifact with no corresponding APPROVED finding is a false negative.

Findings emitted on a `known_good/` image are all false positives by definition.

## Sources Used (no redistribution)

| Source | Type | License / Access | What it tests |
|---|---|---|---|
| SANS SRL FOR508 lab scenario | known_bad | SANS course license; reference only | Multi-host APT-style intrusion, classic Windows artifacts |
| DFIR Madness (Kevin Pagano) | known_bad | CC BY-NC-SA 4.0; free download | Standalone Windows compromise, browser/USB IOCs |
| AboutDFIR challenges | known_bad | Per-challenge license | Variety of Windows attack scenarios |
| Trace Labs OSINT-derived images | known_bad | CC BY-SA; community | Lower-skill compromise patterns |
| TryHackMe IR labs (purchased) | known_bad | TryHackMe ToS; account required | Quick triage scenarios |
| Find Evil! hackathon sample case | known_bad | Hackathon data (Egnyte link) | The case the judges will probably run against |
| Custom clean baselines | known_good | Self-generated under MIT | Negative-control silence rate |
| Crafted poisoned evidence (this repo) | adversarial | Apache 2.0 (this repo) | Prompt-injection resistance |

## Reproducing the Numbers

```bash
cd corpus
./download.sh   # fetches images, verifies hashes
cd ..
python -m eval.harness --corpus corpus/
```

The script will skip any image whose download is gated behind a paid account and print a warning. Published numbers in [ACCURACY.md](../ACCURACY.md) note which images were excluded for the published run.
