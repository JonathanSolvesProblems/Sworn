# Try SWORN

SWORN is designed to run on the SANS SIFT Workstation. The instructions below assume the SIFT 2025 OVA (Ubuntu 22.04 base).

## Prerequisites

1. Download the SIFT Workstation OVA from <https://sans.org/tools/sift-workstation> and import it in VMware Workstation, VMware Fusion, or VirtualBox.
2. Allocate at least 8 GB RAM and 4 vCPU. 16 GB RAM is recommended for memory analysis with Volatility 3.
3. Boot the VM and log in as `sansforensics`.
4. (Optional) Install Protocol SIFT for comparison:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
   ```

## Install SWORN

```bash
cd ~
git clone https://github.com/JonathanSolvesProblems/Sworn.git
cd sworn
./install/install.sh
```

`install.sh` does the following:
- Verifies SIFT tool versions (Volatility 3 >= 2.5, plaso >= 20240308, Eric Zimmerman tools, Hayabusa, YARA, etc.)
- Creates a Python 3.10 venv at `~/.sworn/venv`
- Installs SWORN and its dependencies
- Generates a per-host Ed25519 keypair under `~/.sworn/keys/` (mode 0600)
- Installs nftables egress rules denying outbound traffic except the LLM provider's endpoint and a configurable list
- Adds a `sworn` symlink to `/usr/local/bin/`

## Acquire the Demo Case

The hackathon provides sample case data at the Egnyte link in the resources section. Download it into `/cases/example/` so you have:

```
/cases/example/
├── disk.E01
├── mem.raw
└── ground_truth.json  (what's actually compromised, used by eval harness)
```

If you do not have access to the hackathon data yet, SWORN will run against any disk image + memory capture pair, but reproducing the published precision/recall numbers requires the same corpus.

## Run a Session

SWORN has two run modes:

**Mode A: Built-in triage (no external LLM required).** Walks every typed tool through the four specialists deterministically, emits the full ledger, and exits. Best for reproducing accuracy numbers and giving judges something they can run without standing up an LLM client.

```bash
sworn triage \
  --case-id DEMO-001 \
  --evidence /cases/example/disk.E01 \
  --memory /cases/example/mem.raw \
  --max-iterations 25
```

**Mode B: MCP gateway for an external LLM client (Claude Code, OpenClaw).** Starts the Inference Constraint Gateway over MCP stdio so an external agent drives the typed tools.

```bash
sworn gateway \
  --case-id DEMO-001 \
  --evidence /cases/example/disk.E01 \
  --memory /cases/example/mem.raw
```

In both modes SWORN will:
1. Hash and register every evidence file
2. Start the Inference Constraint Gateway in-process
3. Stream `actions.jsonl` to `./cases/DEMO-001/actions.jsonl`
4. Stage findings as DRAFT in `./cases/DEMO-001/findings.jsonl` only after corroboration

Optional flags for both modes:
- `--mft /path/to/$MFT` — feed a pre-extracted MFT to the disk specialist
- `--prefetch /path/to/Prefetch` — feed a Prefetch directory to PECmd
- `--chrome-profile /path/to/User\ Data/Default` — feed a Chromium profile to Hindsight
- `--system-hive` / `--software-hive` / `--ntuser-hive` / `--amcache` — point RegRipper at specific hives
- `--evtx /path/to/exported.evtx` — point Hayabusa at exported event logs

## Approve a Finding

Findings are DRAFT until a human approves them:

```bash
sworn findings list --case DEMO-001
sworn findings show <finding_id>
sworn findings approve <finding_id>   # prompts for the approval password
```

The approval HMAC and the examiner identity are appended to the ledger. APPROVED findings can be pushed to TheHive (if configured):

```bash
sworn writeback thehive --case DEMO-001 --hive-url https://thehive.local
```

## Verify Evidence Integrity

```bash
sworn verify evidence --case DEMO-001
sworn verify ledger --case DEMO-001
```

Both commands exit non-zero on tamper. `sworn verify` is also called automatically at session shutdown.

## Reproduce the Accuracy Numbers

```bash
python -m eval.harness --corpus corpus/ --output reports/accuracy.json
```

This is what generates the numbers in [ACCURACY.md](../ACCURACY.md). It runs SWORN against each labeled image in `corpus/` and compares emitted findings against ground truth.

## Negative Control

First run a triage session against the clean baseline image so a ledger is produced. Then pass the resulting case-root to the negative-control harness.

```bash
sworn triage \
  --case-id CLEAN-WIN10 \
  --evidence corpus/known_good/clean_win10_baseline/disk.E01

python -m eval.negative_control --case-root ./cases/CLEAN-WIN10
```

The harness exits zero only if zero DRAFT or APPROVED findings landed. Any non-zero count is a false positive and is reported in [ACCURACY.md](../ACCURACY.md).

## Docker Alternative

```bash
# Build the image locally from the repo:
docker build -t sworn:0.1.0 -f install/Dockerfile .

docker run --rm -it \
  -v /cases:/cases:ro \
  -v $(pwd)/sworn-keys:/root/.sworn/keys \
  sworn:0.1.0 \
  gateway --case-id DEMO-001 --evidence /cases/example/disk.E01 --memory /cases/example/mem.raw
```

The container has all SIFT triage tools pre-installed.
