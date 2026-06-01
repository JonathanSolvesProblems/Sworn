# What's Next

SWORN v0.1.0 is a 18-day hackathon entry, not a finished product. The list below is what production-readiness would require, ordered by impact. Each item is an honest gap, not a roadmap promise.

## Coverage gaps (the things SWORN does not yet do)

### Cloud forensics
Typed wrappers for cloud audit logs and runtime forensics:
- AWS: CloudTrail event ingest, GuardDuty findings, EC2 IMDS access logs, EBS snapshot acquisition
- Azure: Activity Log, Sign-in Log, Defender for Cloud alerts, VHD snapshot
- GCP: Audit Log, Security Command Center, Persistent Disk snapshot

The corroboration rules in [sworn/corroboration/__init__.py](../sworn/corroboration/__init__.py) would gain cloud-specific artifact families (e.g. `aws_cloudtrail_assume_role`, `azure_signin_anomalous_location`, `gcp_iam_serviceaccountkey_create`).

### Mobile forensics
- iOS: integrate mvt-mobile (Mobile Verification Toolkit) and iLEAPP
- Android: ALEAPP, MSAB-style logical extractions

Adds artifact families for `ios_keychain`, `android_app_data`, `apple_pegasus_iocs`.

### Full kernel-level evidence integrity
The current evidence-integrity story (see [evidence-integrity.md](evidence-integrity.md)) layers OS-level read-only bind mounts plus SHA-256 re-verification plus typed-wrapper path validation. What's missing for production:
- FUSE-based write-blocker so even root cannot mutate the evidence path
- SELinux MAC labels denying write to the evidence FS context label
- TPM-backed Ed25519 keys (the current keys live on disk under `~/.sworn/keys/` with mode 0600)
- Hardware write-blocker integration for live acquisition

### Real-time SIEM streaming
Today SWORN runs over static images. Production triage often runs against live SIEM streams. Needed:
- Splunk / Elastic / Sentinel ingest wrappers as MCP tools
- Bounded-rate streaming so a noisy index does not blow the LLM context
- Time-window scoping primitives in the gateway

### Live endpoint via Velociraptor
Wrap Velociraptor artifacts and the offline collector as typed MCP functions. This is what closes the gap between SWORN-as-image-triage and SWORN-as-live-IR.

### YARA rule curation
SWORN ships **no** YARA rules in the repo (third-party licensing). The installer can fetch Florian Roth's signature-base on opt-in (`SWORN_FETCH_YARA=1`). Production deployments should curate their own ruleset and version-pin it in the ledger as part of `report_metadata`.

## Architectural gaps

### LLM token usage in the ledger
The `Invocation` dataclass logs `latency_ms` but not `tokens_estimated`. When an LLM client drives the gateway, the client should attribute its token usage per turn into a separate `llm_turn` ledger entry. Schema and wiring are not yet in place.

### Approval workflow UX
Today `sworn findings approve` is CLI-only and uses a single PBKDF2 passphrase per host. Multi-examiner approval (e.g. two-person rule for high-severity findings) is not yet implemented. The ledger already supports it; the CLI does not.

### Examiner identity binding
The HMAC ties an approval to the passphrase, not to a strong examiner identity. A production deployment would bind to an OIDC issuer or a smartcard-backed signing key (PIV, YubiKey FIDO2).

## Validation gaps

### Court admissibility
SWORN is a defensible-methodology demonstrator, not a certified forensic tool. Path to admissibility:
- Independent peer review of the corroboration rules
- Reproducibility study on a public labeled corpus larger than what SWORN ships
- Prospective sensitivity / specificity study against a gold standard maintained by NIST or similar
- ASCLD/LAB or equivalent accreditation of the lab using SWORN

The Daubert factors named in [regulatory-mappings.md](regulatory-mappings.md) are mapped, not satisfied.

### Adversarial corpus expansion
The current adversarial corpus under [adversarial/](../adversarial/) covers a small set: forged invocation IDs, hash swaps, single-family findings, poisoned EVTX messages. Production-grade red-teaming should also exercise:
- Tool-poisoning attacks (compromise a SIFT binary, see if SWORN's pinned-wheel + git-SHA check catches it)
- Side-channel timing attacks against the gateway
- Resource exhaustion (a 100 GB memory image, a recursive symlink in the evidence root)

## What this list is not

It is not a roadmap commitment. It is the honest answer to "what would it take to put SWORN behind a real engagement." Each gap is documented because the court-admissibility judges on the Find Evil! panel (Carr, Carroll, Rankhorn, Wilson, Brawner) consistently warn against overclaim. The path to production runs through these gaps, and the path to court runs further than that.

See [README.md](../README.md) for what SWORN does do today, and [ACCURACY.md](../ACCURACY.md) for measured numbers.
