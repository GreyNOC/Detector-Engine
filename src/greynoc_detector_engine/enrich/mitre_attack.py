from __future__ import annotations

from greynoc_detector_engine.utils.text import keyword_hits

TECHNIQUE_KEYWORDS: dict[str, list[str]] = {
    # Initial Access
    "T1190": ["exposed", "internet-facing", "public-facing", "exploit public-facing"],
    "T1133": ["vpn", "rdp gateway", "remote service"],
    "T1566": ["phishing", "spear-phish", "malicious attachment"],
    "T1078": ["valid accounts", "stolen credentials", "compromised credential"],
    # Execution
    "T1059": ["powershell", "cmd.exe", "bash", "shell"],
    "T1203": ["client execution", "user execution"],
    "T1106": ["api call", "native api"],
    # Persistence
    "T1098": ["account manipulation", "added admin"],
    "T1136": ["created account", "rogue account"],
    # Privilege Escalation
    "T1068": ["privilege escalation", "elevation", "uac bypass"],
    "T1548": ["abuse elevation"],
    # Defense Evasion
    "T1027": ["obfuscated", "obfuscation", "packed payload"],
    "T1562": ["disable defenses", "disable edr", "stop antivirus"],
    # Credential Access
    "T1003": ["mimikatz", "lsass", "credential dumping"],
    "T1110": ["brute force", "password spray", "credential stuffing"],
    # Discovery
    "T1018": ["remote system discovery"],
    "T1046": ["network scan", "port scan"],
    # Lateral Movement
    "T1021": ["lateral movement", "smb", "wmi", "psexec"],
    "T1570": ["lateral tool transfer"],
    # Collection
    "T1005": ["data from local system"],
    "T1213": ["sharepoint", "confluence", "internal wiki"],
    # Command and Control
    "T1071": ["application layer protocol", "c2 over http"],
    "T1573": ["encrypted channel", "tls c2"],
    # Exfiltration
    "T1041": ["exfiltrate over c2"],
    "T1567": ["exfiltrate to cloud", "exfiltrate to web service"],
    # Impact
    "T1486": ["ransomware", "encrypt files for impact"],
    "T1490": ["inhibit system recovery"],
    "T1485": ["data destruction", "wiper"],
    # AI-attack overlays (custom)
    "AML.T0051": ["prompt injection", "indirect prompt injection"],
    "AML.T0043": ["model jailbreak", "jailbreak"],
    "AML.T0024": ["data poisoning"],
    "AML.T0048": ["rag poisoning"],
}


class MitreAttackInferrer:
    """Heuristic MITRE ATT&CK / ATLAS technique tagging from public text."""

    def infer(self, text: str) -> list[str]:
        haystack = (text or "").lower()
        techniques: list[str] = []
        for technique_id, terms in TECHNIQUE_KEYWORDS.items():
            if keyword_hits(haystack, terms):
                techniques.append(technique_id)
        return sorted(set(techniques))
