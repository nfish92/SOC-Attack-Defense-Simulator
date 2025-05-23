# defense_simulator.py
"""
Defense Simulator Module (Enhanced)
Maps attack events to realistic, multi-stage defense actions and recommendations.
Includes probabilistic outcomes, user guidance, and escalation logic.
"""

from datetime import datetime, timedelta
import random

# Analyst names for attribution
ANALYSTS = [
    "SOC Analyst Alice", "SOC Analyst Bob", "SOC Analyst Carol",
    "EDR System", "Firewall Appliance", "WAF Gateway", "Vuln Mgmt System"
]

# Main defense actions with recommendations and escalation logic
DEFENSE_ACTIONS = {
    "Broken Access Control": {
        "responses": [
            {"action": "Blocked by IAM/ACL", "system": "Identity & Access Mgmt", "success_rate": 0.98},
            {"action": "Alert SOC team for investigation", "system": "SIEM", "success_rate": 1.0}
        ],
        "recommendation": "Review IAM roles and policies. Investigate potential privilege escalation.",
        "escalation_required": True
    },
    "Cryptographic Failures": {
        "responses": [
            {"action": "Alert generated, not blocked", "system": "SIEM", "success_rate": 0.9}
        ],
        "recommendation": "Ensure all sensitive data is transmitted over TLS 1.2+ and disable insecure protocols.",
        "escalation_required": True
    },
    "Injection (SQLi)": {
        "responses": [
            {"action": "Blocked by WAF", "system": "Web App Firewall", "success_rate": 0.94},
            {"action": "Alert DevSecOps", "system": "SIEM", "success_rate": 1.0}
        ],
        "recommendation": "Implement parameterized queries and validate user input. Review app for injection risks.",
        "escalation_required": True
    },
    "Insecure Design": {
        "responses": [
            {"action": "Flagged for dev review", "system": "DevSecOps", "success_rate": 0.5}
        ],
        "recommendation": "Apply secure SDLC practices. Review app logic and add input validation.",
        "escalation_required": False
    },
    "Security Misconfiguration": {
        "responses": [
            {"action": "Blocked by hardened config", "system": "Server Hardening", "success_rate": 0.95},
            {"action": "Alert sysadmin", "system": "SIEM", "success_rate": 1.0}
        ],
        "recommendation": "Audit server configs. Disable directory listing and remove unused services.",
        "escalation_required": False
    },
    "Vulnerable and Outdated Components": {
        "responses": [
            {"action": "Alert - Patch Required", "system": "Vulnerability Scanner", "success_rate": 1.0}
        ],
        "recommendation": "Patch or update vulnerable libraries: run `pip list --outdated` or use your package manager.",
        "escalation_required": True
    },
    "Identification and Authentication Failures": {
        "responses": [
            {"action": "Account locked after failed logins", "system": "IAM/EDR", "success_rate": 0.99},
            {"action": "Alert SOC", "system": "SIEM", "success_rate": 1.0}
        ],
        "recommendation": "Enforce strong password policies and enable MFA.",
        "escalation_required": False
    },
    "Software and Data Integrity Failures": {
        "responses": [
            {"action": "Blocked by file integrity monitoring", "system": "FIM/EDR", "success_rate": 0.90}
        ],
        "recommendation": "Enable code signing. Verify integrity of all third-party packages.",
        "escalation_required": True
    },
    "Security Logging and Monitoring Failures": {
        "responses": [
            {"action": "No alert - detection failed", "system": "SIEM", "success_rate": 0.1}
        ],
        "recommendation": "Audit log sources and SIEM configs. Ensure all events are ingested.",
        "escalation_required": True
    },
    "Server-Side Request Forgery (SSRF)": {
        "responses": [
            {"action": "Blocked by SSRF filter", "system": "Web App Firewall", "success_rate": 0.93}
        ],
        "recommendation": "Implement allow-list for outgoing requests and validate user input.",
        "escalation_required": True
    },
    "Port Scan": {
        "responses": [
            {"action": "Firewall dropped SYNs", "system": "Firewall", "success_rate": 0.97}
        ],
        "recommendation": "Restrict unnecessary ports and monitor for repeated scan attempts.",
        "escalation_required": False
    },
    "Phishing Email": {
        "responses": [
            {"action": "Blocked by mail gateway", "system": "Mail Security", "success_rate": 0.92},
            {"action": "User-reported phishing", "system": "SOC", "success_rate": 1.0}
        ],
        "recommendation": "Educate users about phishing. Run phishing simulation campaigns.",
        "escalation_required": False
    },
    "Insider Data Exfiltration": {
        "responses": [
            {"action": "Flagged by EDR/SIEM", "system": "EDR/SIEM", "success_rate": 0.92},
            {"action": "SOC investigation started", "system": "SOC", "success_rate": 1.0}
        ],
        "recommendation": "Investigate user activity. Apply DLP rules and restrict mass downloads.",
        "escalation_required": True
    },
    "Malware Dropper": {
        "responses": [
            {"action": "Quarantined by EDR", "system": "EDR", "success_rate": 0.93},
            {"action": "Alert SOC team", "system": "SIEM", "success_rate": 1.0}
        ],
        "recommendation": "Scan affected hosts with antivirus. Educate users about file downloads.",
        "escalation_required": True
    },
    "Zero-Day Ransomware": {
        "responses": [
            {"action": "EDR attempted block - partial success", "system": "EDR", "success_rate": 0.7},
            {"action": "Escalated to IR team", "system": "SOC", "success_rate": 1.0}
        ],
        "recommendation": "Isolate affected systems immediately. Restore from backups. Patch vulnerabilities.",
        "escalation_required": True
    },
}

def pick_analyst(system):
    """Randomly assign a defense system or SOC analyst for attribution."""
    if "SOC" in system or "SIEM" in system:
        return random.choice([a for a in ANALYSTS if "SOC" in a or "SIEM" in a])
    if "WAF" in system:
        return "WAF Gateway"
    if "Firewall" in system:
        return "Firewall Appliance"
    if "EDR" in system:
        return "EDR System"
    if "Vulnerability" in system:
        return "Vuln Mgmt System"
    if "Mail" in system:
        return "Mail Security"
    return random.choice(ANALYSTS)

class DefenseSimulator:
    def __init__(self):
        pass

    def defend_event(self, attack_event):
        """
        For a given attack event (dict), attach defense actions, recommendations, escalation.
        """
        action_bundle = DEFENSE_ACTIONS.get(
            attack_event["attack_type"],
            {
                "responses": [{"action": "Monitored by SIEM", "system": "SIEM", "success_rate": 1.0}],
                "recommendation": "Monitor and investigate as needed.",
                "escalation_required": False
            }
        )

        # Choose a primary defense response (simulate success/failure)
        responses = action_bundle["responses"]
        chosen = random.choice(responses)
        succeeded = random.random() < chosen["success_rate"]
        # Simulate response time
        min_time, max_time = (1, 30) if succeeded else (10, 120)
        response_time = random.randint(min_time, max_time)
        defense_timestamp = (
            datetime.strptime(attack_event["timestamp"], "%Y-%m-%d %H:%M:%S") +
            timedelta(seconds=response_time)
        ).strftime("%Y-%m-%d %H:%M:%S")

        # Add escalation and recommendations
        defense_event = attack_event.copy()
        defense_event.update({
            "defense_action": chosen["action"],
            "defense_system": chosen["system"],
            "defense_success": succeeded,
            "defense_analyst": pick_analyst(chosen["system"]),
            "defense_response_time_sec": response_time,
            "defense_timestamp": defense_timestamp,
            "recommendation": action_bundle.get("recommendation", ""),
            "escalation_required": action_bundle.get("escalation_required", False)
        })

        # If not successful and escalation required, add urgent escalation
        if not succeeded and action_bundle.get("escalation_required", False):
            defense_event["urgent_escalation"] = "Incident Response Team Notified"

        return defense_event

    def defend_events_bulk(self, attack_events):
        """Apply defense logic to a list of attack events."""
        return [self.defend_event(ev) for ev in attack_events]

    def defend_event(self, attack_event):
        # Handle missed logs
        if not attack_event.get("is_logged", True):
            return {
                **attack_event,
                "defense_action": "No response - event not detected (see missed_log_context)",
                "defense_system": "",
                "defense_success": False,
                "defense_analyst": "",
                "defense_response_time_sec": None,
                "defense_timestamp": None,
                "recommendation": "Audit and restore full logging pipeline. Investigate missed detection.",
                "escalation_required": True,
                "urgent_escalation": "Log pipeline/SIEM admin notified"
            }

        # Handle benign events (false positives)
        if not attack_event.get("is_true_positive", True):
            return {
                **attack_event,
                "defense_action": f"No action - benign activity: {attack_event.get('benign_reason', '')}",
                "defense_system": "",
                "defense_success": True,
                "defense_analyst": "",
                "defense_response_time_sec": 0,
                "defense_timestamp": attack_event["timestamp"],
                "recommendation": "Review alert tuning to reduce false positives.",
                "escalation_required": False
            }

        # Normal mapped defense
        action_bundle = DEFENSE_ACTIONS.get(
            attack_event["attack_type"],
            {
                "responses": [{"action": "Monitored by SIEM", "system": "SIEM", "success_rate": 1.0}],
                "recommendation": "Monitor and investigate as needed.",
                "escalation_required": False
            }
        )

        responses = action_bundle["responses"]
        chosen = random.choice(responses)
        succeeded = random.random() < chosen["success_rate"]
        min_time, max_time = (1, 30) if succeeded else (10, 120)
        response_time = random.randint(min_time, max_time)
        defense_timestamp = (
            datetime.strptime(attack_event["timestamp"], "%Y-%m-%d %H:%M:%S") +
            timedelta(seconds=response_time)
        ).strftime("%Y-%m-%d %H:%M:%S")

        defense_event = attack_event.copy()
        defense_event.update({
            "defense_action": chosen["action"],
            "defense_system": chosen["system"],
            "defense_success": succeeded,
            "defense_analyst": pick_analyst(chosen["system"]),
            "defense_response_time_sec": response_time,
            "defense_timestamp": defense_timestamp,
            "recommendation": action_bundle.get("recommendation", ""),
            "escalation_required": action_bundle.get("escalation_required", False)
        })

        if not succeeded and action_bundle.get("escalation_required", False):
            defense_event["urgent_escalation"] = "Incident Response Team Notified"

        return defense_event

# Example usage:
# if __name__ == "__main__":
#     from attack_simulator import AttackSimulator
#     atk_sim = AttackSimulator()
#     def_sim = DefenseSimulator()
#     events = atk_sim.generate_mixed_activity(10)
#     for event in def_sim.defend_events_bulk(events):
#         print(event)
