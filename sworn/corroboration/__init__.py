"""Cross-tool corroboration rules.

Moat #3 of SWORN: a finding of a given class requires evidence from at least
N distinct artifact families. Single-source claims do not reach DRAFT.

The rule is enforced by the Inference Constraint Gateway, not by a prompt.
"""

from __future__ import annotations

from dataclasses import dataclass

from sworn.findings.schema import Finding, FindingClass, FindingState


@dataclass(frozen=True)
class CorroborationRule:
    finding_class: FindingClass
    min_distinct_families: int
    allowed_families: frozenset[str]

    def satisfied_by(self, finding: Finding) -> bool:
        families = finding.artifact_families()
        relevant = families & self.allowed_families
        return len(relevant) >= self.min_distinct_families


_RULES: dict[FindingClass, CorroborationRule] = {
    FindingClass.execution: CorroborationRule(
        finding_class=FindingClass.execution,
        min_distinct_families=2,
        allowed_families=frozenset(
            {
                "amcache",
                "prefetch",
                "shimcache",
                "evtx_security_4688",
                "evtx_sysmon_1",
                "userassist",
                "bam_dam",
                "srum",
                "mft_lnk",
                "syscache",
            }
        ),
    ),
    FindingClass.persistence: CorroborationRule(
        finding_class=FindingClass.persistence,
        min_distinct_families=2,
        allowed_families=frozenset(
            {
                "run_key",
                "scheduled_task",
                "wmi_subscription",
                "service_install",
                "startup_folder",
                "image_file_execution_options",
                "applnit_dlls",
                "winlogon_shell_userinit",
            }
        ),
    ),
    FindingClass.lateral_movement: CorroborationRule(
        finding_class=FindingClass.lateral_movement,
        min_distinct_families=2,
        allowed_families=frozenset(
            {
                "evtx_security_4624_logon",
                "evtx_security_4648_explicit_creds",
                "evtx_security_4672_special_priv",
                "rdp_bitmap_cache",
                "psexec_event_log",
                "wmi_provider",
                "smb_connection",
                "kerberos_4769",
                "evtx_remote_desktop_1149",
            }
        ),
    ),
    FindingClass.credential_access: CorroborationRule(
        finding_class=FindingClass.credential_access,
        min_distinct_families=2,
        allowed_families=frozenset(
            {
                "lsass_dump",
                "sam_hive_access",
                "ntds_dit_access",
                "evtx_security_4776",
                "mimikatz_yara",
                "dcsync_4662",
                "registry_secrets",
            }
        ),
    ),
    FindingClass.defense_evasion: CorroborationRule(
        finding_class=FindingClass.defense_evasion,
        min_distinct_families=2,
        allowed_families=frozenset(
            {
                "evtx_security_1102_log_cleared",
                "timestomp_mft",
                "wevtutil_clear",
                "av_disabled",
                "amsi_bypass_event",
                "etw_patch",
                "unsigned_driver_load",
            }
        ),
    ),
    FindingClass.exfiltration: CorroborationRule(
        finding_class=FindingClass.exfiltration,
        min_distinct_families=2,
        allowed_families=frozenset(
            {
                "srum_network_bytes",
                "browser_uploads",
                "rclone_artifact",
                "cloud_cli_artifact",
                "smb_outbound",
                "dns_exfil_pattern",
            }
        ),
    ),
}


def rule_for(finding_class: FindingClass) -> CorroborationRule | None:
    return _RULES.get(finding_class)


def gated_state(finding: Finding) -> FindingState:
    """Decide the state a freshly-submitted finding should have.

    Returns:
        DRAFT if the corroboration rule for the finding's class is satisfied.
        INDICATION otherwise. APPROVED and REJECTED are operator transitions
        only; the gateway never returns them from here.
    """
    rule = rule_for(finding.finding_class)
    if rule is None:
        return FindingState.indication
    return FindingState.draft if rule.satisfied_by(finding) else FindingState.indication


__all__ = ["CorroborationRule", "rule_for", "gated_state"]
