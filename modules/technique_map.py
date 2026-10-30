"""
modules/technique_map.py

Authoritative technique declarations for the cycle 3 defensive layer.

MODULE_TECHNIQUES maps each menu module (key = file stem under
modules/, or 'agent._core' for the agent tool implementations) to
the MITRE ATT&CK technique IDs that module's findings carry. For
modules that record findings, the list is the union of the literal
technique_ids= arguments at that module's add_finding() call sites;
the cycle 3 test suite enforces that the call sites and this map
stay in sync. The six finding-less modules carry hand declarations
describing what they test (no findings exist to tag).

EXCEPTIONS lists findings that deliberately carry no technique:
they evidence no attack technique, and forcing an ID would be
fabrication. Report-time keyword inference may still apply to them.
"""
from __future__ import annotations

# Module key -> sorted technique IDs (all must exist in
# modules/mitre_data.py TECHNIQUES).
MODULE_TECHNIQUES: dict[str, list[str]] = {
    "acl_abuse": ["T1003.006", "T1222", "T1558"],
    "ad_abuse_extra": ["T1003.003", "T1098", "T1136.002", "T1222", "T1484.001", "T1543", "T1557.001", "T1558.003"],
    "ad_advanced_playbook": ["T1047", "T1484.002", "T1562.001"],
    "adfs_attacks": ["T1528", "T1606.002"],
    "adidns_abuse": ["T1543", "T1557.001"],
    "agent._core": ["T1003.001", "T1003.002", "T1003.006", "T1018", "T1021.002", "T1021.006", "T1068", "T1069.002", "T1072", "T1078.002", "T1082", "T1087.002", "T1098", "T1110.003", "T1134.001", "T1187", "T1222", "T1482", "T1505.001", "T1543", "T1547", "T1552", "T1555", "T1557.001", "T1558", "T1558.001", "T1558.002", "T1558.003", "T1558.004", "T1649"],
    "aitm_mfa_bypass": ["T1078.002", "T1098", "T1528"],
    "amsi_bypass": ["T1027", "T1562.001"],
    "azure_ad": ["T1078.004", "T1098", "T1528", "T1606.002"],
    "bloodhound_helper": ["T1069.002", "T1087.002", "T1482"],
    "c2_integration": ["T1059.001"],
    "cert_abuse": ["T1003.006", "T1557.001", "T1649"],
    "coercion_attacks": ["T1134.001", "T1187", "T1557.001", "T1558", "T1649"],
    "credential_dump": ["T1003.001", "T1003.003", "T1003.006", "T1555"],
    "cve_exploits": ["T1068", "T1134.001", "T1187", "T1557.001"],
    "dcsync_dcshadow": ["T1003.006"],
    "dnsadmins_abuse": ["T1543", "T1557.001"],
    "dpapi_creds": ["T1003.006", "T1555", "T1649"],
    "edr_evasion": ["T1003.001", "T1082", "T1562.001"],
    "entra_hybrid_attacks": ["T1003.006", "T1098", "T1555", "T1558.002"],
    "enum_ad": ["T1018", "T1069.002", "T1083", "T1087.002", "T1482", "T1552"],
    "exploit_chains": ["T1003.006", "T1069.002", "T1087.002", "T1134.001", "T1222", "T1482", "T1558", "T1558.001", "T1558.003", "T1558.004", "T1649"],
    "gmsa_attacks": ["T1555", "T1558"],
    "golden_certificate": ["T1558", "T1649"],
    "gpo_abuse": ["T1053.005", "T1484.001"],
    "initial_access": ["T1557.001"],
    "jea_attacks": ["T1552"],
    "kerberos_attacks": ["T1134.001", "T1558", "T1558.001", "T1558.003", "T1558.004"],
    "lateral_movement": ["T1021.006"],
    "local_persistence": ["T1053.005", "T1098", "T1547"],
    "local_privesc": ["T1068", "T1134.001"],
    "loot_parser": ["T1003.001", "T1003.003", "T1558.001"],
    "m365_teams_attacks": ["T1072", "T1078.004", "T1087.002", "T1098", "T1528", "T1590", "T1598"],
    "mssql_abuse": ["T1505.001"],
    "netexec_suite": ["T1021.002", "T1021.006", "T1046", "T1087.002"],
    "network_discovery": ["T1557.001"],
    "password_attacks": ["T1110.003"],
    "persistence": ["T1003.006", "T1047", "T1053.005", "T1098", "T1134.001", "T1222", "T1484.002", "T1543", "T1547", "T1558.001", "T1558.002"],
    "powerview_enum": ["T1552"],
    "pre2k_timeroast": ["T1078.002", "T1136.002", "T1558.004"],
    "rbcd_attacks": ["T1134.001", "T1557.001"],
    "recon_osint": ["T1590", "T1596", "T1598"],
    "rodc_attacks": ["T1003.003", "T1187", "T1557.001", "T1558.001"],
    "rubeus_module": ["T1134.001", "T1550.002"],
    "sccm_abuse": ["T1072", "T1098", "T1552", "T1557.001"],
    "shadow_copies": ["T1003.003"],
    "shadow_credentials": ["T1557.001", "T1558"],
    "snaffler_hunter": ["T1552"],
    "trust_attacks": ["T1484.002", "T1558", "T1558.001"],
    "uac_bypass": ["T1548.002"],
    "unpac_passthecert": ["T1558.003", "T1649"],
    "user_hunting": ["T1018", "T1078.002"],
    "wsus_attack": ["T1072", "T1649"],
}

# (module key, exact finding name) -> reason for no technique tag.
EXCEPTIONS: dict[tuple[str, str], str] = {
    ("ad_advanced_playbook", "AD Deception Validation Planned"):
        "Planning artifact: records that deception validation was planned, not an observed attack technique.",
    ("golden_certificate", "ADCS Scan Complete"):
        "Scan-completion note (Info): records that a certipy scan finished, not a vulnerability; the ESC findings above carry the techniques.",
}


def techniques_for(module_key: str) -> list[str]:
    """Return the declared techniques for a module (copy)."""
    return list(MODULE_TECHNIQUES.get(module_key, []))
