# corpus/known_bad/findevil_sample_case

The hackathon-provided sample case from the Find Evil! resources (the Egnyte link in the Devpost resources panel: `https://sansorg.egnyte.com/fl/HhH7crTYT4JK`). Used as the headline known-bad case for SWORN's accuracy run.

## How to obtain

1. Open the Egnyte link in the Find Evil! resources panel.
2. Download every artifact the hackathon publishes (typically a `disk.E01`, a `mem.raw`, and maybe extracted artifacts like `$MFT` or a Prefetch directory).
3. Drop the files into this directory next to this README.

If the Egnyte link is not reachable on the day, the closest viable replacement is the **DFIR Madness 2022 challenge** (Kevin Pagano, CC BY-NC-SA 4.0). Update `case_id` and `source` in `ground_truth.json` accordingly.

## Files in this directory

- `README.md`: this file
- `ground_truth.json`: template with the artifact schema; fill in the labeled artifacts after reading the case briefing
- `download.sh`: optional, manual download is acceptable

## Filling in `ground_truth.json`

For each compromise artifact the case briefing names (mimikatz exec, persistence via Run-key, lateral movement via 4624 logon, etc.), add a record under `artifacts` with:

- `kind`: one of `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`
- `description`: one sentence
- `evidence`: list of `{tool, ...}` records pointing at the deterministic-tool outputs SWORN should cite
- `mitre`: list of ATT&CK technique IDs (e.g. `T1003.001`)
- `severity`: `critical`, `high`, `medium`, `low`, `informational`

The eval harness uses these to score per-class precision and recall. Be conservative: only label artifacts the case briefing actually proves.
