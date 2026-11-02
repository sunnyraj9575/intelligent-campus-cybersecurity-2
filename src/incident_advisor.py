"""
Incident Response and Mitigation Advisory Engine for Campus Cyber Defense.
Maps detected threats to MITRE ATT&CK techniques, risk severity, and concrete containment actions.
"""

from typing import Any, Dict


class IncidentAdvisor:
    """Generates tactical and automated mitigation advisories for detected threats."""

    ADVISORIES: Dict[str, Dict[str, Any]] = {
        "Benign": {
            "severity": "Info",
            "risk_score": 1,
            "mitre_id": "N/A",
            "mitre_name": "Normal Operation",
            "description": "Standard legitimate campus network traffic complying with acceptable use policies.",
            "recommended_action": "No remediation required. Maintain standard telemetry logging.",
            "firewall_rule": "ACCEPT",
            "containment_tier": "Tier-0 (Monitor Only)",
        },
        "DDoS_Flood": {
            "severity": "Critical",
            "risk_score": 10,
            "mitre_id": "T1498",
            "mitre_name": "Network Denial of Service (Direct Flooding)",
            "description": "Volumetric flood targeting university server farm / student registration portal.",
            "recommended_action": "Enable upstream BGP Blackholing / Anycast Scrubbing. Apply router ingress rate-limiting.",
            "firewall_rule": "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT\niptables -A INPUT -p tcp --syn -j DROP",
            "containment_tier": "Tier-3 (Immediate Edge Mitigation)",
        },
        "Brute_Force": {
            "severity": "High",
            "risk_score": 8,
            "mitre_id": "T1110",
            "mitre_name": "Brute Force (Credential Guessing)",
            "description": "Repeated failed authentication attempts against campus SSH/FTP/Admin systems.",
            "recommended_action": "Temporarily lock targeted account, trigger 2FA challenge, enforce IP jail time in fail2ban.",
            "firewall_rule": "iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP",
            "containment_tier": "Tier-2 (Host-level Quarantine & Account Freeze)",
        },
        "Port_Scan": {
            "severity": "Medium",
            "risk_score": 6,
            "mitre_id": "T1046",
            "mitre_name": "Network Service Discovery (Reconnaissance)",
            "description": "Systematic probing of campus host ports to identify exploitable open services.",
            "recommended_action": "Block scanner IP on core campus switch. Log reconnaissance pattern to SIEM.",
            "firewall_rule": "iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP\niptables -A INPUT -m recent --name portscan --remove",
            "containment_tier": "Tier-1 (Edge ACL Temporary Block)",
        },
        "Web_Attack": {
            "severity": "Critical",
            "risk_score": 9,
            "mitre_id": "T1190",
            "mitre_name": "Exploit Public-Facing Application (SQLi / XSS)",
            "description": "Malicious HTTP payload injection targeting campus web applications and databases.",
            "recommended_action": "Activate WAF virtual patching. Sanitize student portal input fields. Review database audit logs.",
            "firewall_rule": "modsecurity_rules: SecRule REQUEST_URI|REQUEST_BODY \"(?i)(union.*select|insert.*into|<script>)\" \"id:1001,phase:2,deny,status:403\"",
            "containment_tier": "Tier-3 (Immediate WAF Ingress Drop)",
        },
        "Botnet_C2": {
            "severity": "Critical",
            "risk_score": 9,
            "mitre_id": "T1071",
            "mitre_name": "Application Layer Protocol (Command and Control Beaconing)",
            "description": "Compromised computer lab or student workstation establishing beaconing to external C2 server.",
            "recommended_action": "Quarantine workstation MAC address to isolated VLAN (802.1X). Initiate host malware scan.",
            "firewall_rule": "cisco-ios: access-list 101 deny ip host <SRC_IP> any\naccess-list 101 deny ip any host <C2_IP>",
            "containment_tier": "Tier-3 (Physical Port VLAN Isolation)",
        },
        "Data_Exfiltration": {
            "severity": "Critical",
            "risk_score": 10,
            "mitre_id": "T1048",
            "mitre_name": "Exfiltration Over Alternative Protocol / Unauthorized Transfer",
            "description": "Anomalous high-volume outbound transfer of sensitive campus or student database records.",
            "recommended_action": "Sever active TCP connection immediately. Freeze administrative credentials. Notify CISO.",
            "firewall_rule": "tcpkill -9 host <SRC_IP> and dst host <EXT_IP>\niptables -I FORWARD -s <SRC_IP> -j REJECT --reject-with tcp-reset",
            "containment_tier": "Tier-4 (Emergency Session Termination & Legal Hold)",
        },
    }

    @classmethod
    def get_advisory(cls, threat_label: str) -> Dict[str, Any]:
        """Retrieve mitigation playbook for a detected threat class."""
        return cls.ADVISORIES.get(threat_label, cls.ADVISORIES["Benign"])
