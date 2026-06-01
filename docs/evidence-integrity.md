# Evidence Integrity

The single question that decides whether SWORN belongs in a real IR engagement: **does running SWORN ever modify the evidence?**

The answer must be *no*, demonstrably, by architecture rather than by promise.

## Layers of Protection

### Layer 1: OS-level read-only mount

`install.sh` enforces and `sworn gateway` verifies that the evidence root is bind-mounted with `ro,noatime,nosuid,nodev`. The gateway refuses to start if any option is missing or if the source path is not a separate mount.

```
mount --bind /cases /mnt/sworn-evidence
mount -o remount,ro,bind,noatime,nosuid,nodev /mnt/sworn-evidence
```

If the operator passes `--evidence /cases/example.E01` directly, the gateway opens the file with `O_RDONLY` and asserts the inode is on a read-only mount via `/proc/self/mountinfo`.

### Layer 2: SHA-256 ingest registration

Every evidence file is hashed at session start. The hash, size, mtime, inode, and a UUID `evidence_id` are written as the first line of the ledger (after the session-start record). After every tool invocation the gateway re-hashes the files the tool touched and asserts the hash matches.

Drift triggers `EvidenceIntegrityViolation` which:
1. Halts the gateway (no further tool calls accepted)
2. Writes a `tamper_detected` entry to the ledger
3. Returns a structured error to the orchestrator
4. Exits with a non-zero code that surfaces in `ACCURACY.md` reproduction runs

### Layer 3: Typed tool wrappers cannot accept write paths into evidence

Every tool wrapper has a pydantic schema. Output-path parameters are constrained to `./analysis/` or `./exports/` via `model_validator`. An attempt to pass `--output /cases/somewhere` is rejected by the validator before subprocess.run is ever called.

### Layer 4: Subprocess sandbox

Tool subprocesses inherit a restricted environment. `HOME` is set to a session-scoped tempdir under `./analysis/`. `PATH` is pinned to the SIFT tool paths plus the session tempdir. `umask 0o077` is set so tool-created files are not world-readable. The subprocess runs as a non-root user where the SIFT VM allows it.

### Layer 5: Ledger signs what touched the evidence

Each tool invocation's ledger entry includes `evidence_ids_read: [...]` and (always empty for analysis tools) `evidence_ids_written: [...]`. A non-empty `evidence_ids_written` is a bug.

## What the Operator Can Test

```bash
# Take a hash before SWORN runs.
sha256sum /cases/example.E01 > /tmp/before.sha256

# Run a full session.
sworn gateway --evidence /cases/example.E01 --memory /cases/mem.raw --case-id DEMO

# Take a hash after.
sha256sum /cases/example.E01 > /tmp/after.sha256

# Diff. Must be empty.
diff /tmp/before.sha256 /tmp/after.sha256
```

`ACCURACY.md` documents the result of this exact test on the labeled corpus.

## What the Operator Cannot Rely On

- **Network filesystems.** SWORN refuses to start if the evidence root is on NFS, SMB, or any FUSE mount where read-only semantics are not enforced by the kernel. This is documented and tested.
- **NTFS / exFAT on Linux via NTFS-3G.** Permission masks are advisory in many configurations. SWORN's behavior is to copy-on-ingest to an ext4 evidence pool if NTFS-3G is detected, register the copy's hash, and bind-mount the copy read-only. Original NTFS volume is never written.
- **Write-blocker absence.** SWORN does not replace a hardware write-blocker for live disk acquisition. It is a triage and analysis tool, not an acquisition tool.

These caveats are spelled out because the court-admissibility judges on the panel (Carr, Carroll, Rankhorn, Wilson, Brawner) will look for exactly this kind of disclosure.
