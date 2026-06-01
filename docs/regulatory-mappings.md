# Regulatory and Standards Mappings

SWORN is not a certified forensic product. It is a defensible-methodology demonstrator. This document maps SWORN's controls to named standards and guidelines so practitioners (and judges) can assess where the design sits on the path to admissibility.

The aim is the language Cheri Carr, Ovie Carroll, Amanda Rankhorn, John Wilson, and Marc Brawner have used in public talks: *"defensible methodology, conservative claims, complete chain of custody."* SWORN should pass the *would-this-survive-cross-examination* sniff test even when it is not yet certified.

## NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response

| 800-86 area | SWORN mapping |
|---|---|
| 3.1 Data collection | Evidence registered with SHA-256 at ingest. Read-only bind-mount (`ro,noatime,nosuid,nodev`). Re-verified after every tool run. |
| 3.2 Examination | Typed MCP wrappers preserve original data. Tool outputs land in `./analysis/`, never overwriting evidence. |
| 3.3 Analysis | Findings cite specific tool invocations; corroboration enforced for class-based claims. |
| 3.4 Reporting | DRAFT findings carry caveats, corroborating artifacts, and confidence. APPROVED findings require human HMAC sign-off. |

## ISO/IEC 27037:2012 — Guidelines for identification, collection, acquisition, and preservation of digital evidence

| 27037 principle | SWORN mapping |
|---|---|
| 5.4.1 Auditability | Append-only Ed25519-signed `actions.jsonl` covering every tool invocation. |
| 5.4.2 Repeatability | Tool arguments captured verbatim. `sworn replay <invocation_id>` re-runs from the ledger. |
| 5.4.3 Reproducibility | Docker image and pinned wheels logged at session start. |
| 5.4.4 Justifiability | Every finding ties to specific deterministic-tool output; the LLM narrates, the tools attest. |

## Federal Rules of Evidence (United States)

| FRE | SWORN mapping |
|---|---|
| FRE 901(a) — Authentication | Hash chain + Ed25519 signatures establish that ledger entries are what they purport to be. |
| FRE 901(b)(9) — Process or system producing accurate result | Accuracy report in [`ACCURACY.md`](../ACCURACY.md) quotes precision, recall, and negative-control silence rate. |
| FRE 902 — Self-authenticating records | Signed ledger entries with publishable public key. |
| FRE 803(6) — Records of regularly conducted activity | Ledger is created as part of regular automated operation, not for litigation purposes. |

## Daubert Factors (Daubert v. Merrell Dow Pharmaceuticals, 1993)

| Daubert factor | SWORN posture |
|---|---|
| Testability | The eval harness in `eval/harness.py` is the test. |
| Peer review and publication | Open source under Apache 2.0; submitted to a SANS-affiliated community hackathon. |
| Known or potential error rate | Quoted in `ACCURACY.md` per finding class. |
| Standards controlling operation | Typed MCP schemas, corroboration rules, signing protocol all versioned. |
| General acceptance | Built on SIFT (18+ years community use) and Protocol SIFT (SANS-endorsed). |

## What SWORN Explicitly Does NOT Claim

- SWORN is **not** validated for forensic soundness in the courtroom sense.
- SWORN is **not** a substitute for a qualified examiner. Findings remain DRAFT until a human with the approval credentials signs them off.
- SWORN does **not** claim to detect zero-days or novel APT activity outside what its underlying deterministic tools detect.
- SWORN's accuracy numbers are bounded by the labeled corpus on which they were measured; they do not generalize beyond it.

These constraints are stated openly because every judge in the court-admissibility cluster has publicly warned against overclaim, and because the alternative is the kind of "*the AI found malware, your honor*" anti-pattern Rob T. Lee specifically criticized.
