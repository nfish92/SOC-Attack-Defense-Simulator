# attack_simulator.py
"""
Attack Simulator Module (Advanced)
- Generates realistic fake cyber attack events (OWASP Top 10 + common attacks)
- Adds MITRE ATT&CK, CVE, defense, patch, playbook, campaign stages, true/false positives, realistic context, and attack-defense pairing
- Ready for plug-and-play with defense/logging/dashboard modules
"""

from datetime import datetime, timedelta
from faker import Faker
import random
import uuid

fake = Faker()

# Helper: Sample MITRE, CVE, defense, patch, playbook steps
MITRE = {
    "Broken Access Control": "T1069: Permission Groups Discovery",
    "Cryptographic Failures": "T1552: Unsecured Credentials",
    "Injection (SQLi)": "T1190: Exploit Public-Facing Application",
    "Insecure Design": "T1609: Container Administration Command",
    "Security Misconfiguration": "T1505: Server Software Component",
    "Vulnerable and Outdated Components": "T1190: Exploit Public-Facing Application",
    "Identification and Authentication Failures": "T1110: Brute Force",
    "Software and Data Integrity Failures": "T1554: Compromise Client Software Binary",
    "Security Logging and Monitoring Failures": "T1562: Impair Defenses",
    "Server-Side Request Forgery (SSRF)": "T1190: Exploit Public-Facing Application",
    "Port Scan": "T1046: Network Service Discovery",
    "Phishing Email": "T1566: Phishing",
    "Insider Data Exfiltration": "T1041: Exfiltration Over C2 Channel",
    "Malware Dropper": "T1204: User Execution",
    "Zero-Day Ransomware": "T1486: Data Encrypted for Impact"
}

CVES = {
    "Broken Access Control": ["CVE-2021-3156", "CVE-2021-3129"],
    "Cryptographic Failures": ["CVE-2014-3566"],
    "Injection (SQLi)": ["CVE-2012-1823", "CVE-2014-3704"],
    "Insecure Design": [],
    "Security Misconfiguration": ["CVE-2018-10933"],
    "Vulnerable and Outdated Components": ["CVE-2015-9251", "CVE-2016-2333"],
    "Identification and Authentication Failures": ["CVE-2021-21985"],
    "Software and Data Integrity Failures": ["CVE-2020-0601"],
    "Security Logging and Monitoring Failures": [],
    "Server-Side Request Forgery (SSRF)": ["CVE-2017-5638"],
    "Port Scan": [],
    "Phishing Email": [],
    "Insider Data Exfiltration": [],
    "Malware Dropper": ["CVE-2017-0144"],
    "Zero-Day Ransomware": []
}

DEFENSES = {
    "Broken Access Control": "Implement strict RBAC and enforce least privilege. Review IAM settings.",
    "Cryptographic Failures": "Force HTTPS and update SSL/TLS settings. Monitor for plaintext credentials.",
    "Injection (SQLi)": "Sanitize all user input and use parameterized queries.",
    "Insecure Design": "Add strong input validation and design threat modeling.",
    "Security Misconfiguration": "Disable directory listing and review server configs.",
    "Vulnerable and Outdated Components": "Patch outdated components, monitor for vulnerable library usage.",
    "Identification and Authentication Failures": "Enable MFA and throttle failed logins. Audit authentication logs.",
    "Software and Data Integrity Failures": "Validate code integrity, monitor dependencies, and limit external scripts.",
    "Security Logging and Monitoring Failures": "Ensure logs are enabled and monitored, audit logging pipeline.",
    "Server-Side Request Forgery (SSRF)": "Restrict server-side HTTP requests, validate input URLs.",
    "Port Scan": "Enable IDS/IPS, block unnecessary ports, monitor scan activity.",
    "Phishing Email": "Use email filtering, user training, and safe link rewrites.",
    "Insider Data Exfiltration": "Monitor for large downloads, apply DLP, alert on sensitive file access.",
    "Malware Dropper": "Enable endpoint AV/EDR and block known malicious hashes.",
    "Zero-Day Ransomware": "Segment networks, frequent backups, ensure EDR detects suspicious encryption."
}

PATCHES = {
    "Broken Access Control": "Audit and patch IAM misconfigurations. Regularly review roles.",
    "Cryptographic Failures": "Update OpenSSL/TLS, enforce secure ciphers.",
    "Injection (SQLi)": "Update vulnerable web frameworks. Apply all DBMS security patches.",
    "Insecure Design": "Implement secure coding standards and frameworks.",
    "Security Misconfiguration": "Harden server and application configs. Disable unused services.",
    "Vulnerable and Outdated Components": "Upgrade all outdated libraries and dependencies.",
    "Identification and Authentication Failures": "Apply vendor authentication patches, rotate keys.",
    "Software and Data Integrity Failures": "Update dependency management tools and lock versions.",
    "Security Logging and Monitoring Failures": "Update SIEM/logging pipeline and monitor health.",
    "Server-Side Request Forgery (SSRF)": "Patch SSRF-prone frameworks. Apply relevant vendor advisories.",
    "Port Scan": "Patch exposed services, close unneeded ports.",
    "Phishing Email": "Update email security platforms.",
    "Insider Data Exfiltration": "Apply endpoint and server patches. Monitor for privilege escalation.",
    "Malware Dropper": "Update endpoint AV/EDR, block known droppers.",
    "Zero-Day Ransomware": "Patch all endpoints, enforce least privilege, monitor for suspicious activity."
}

PLAYBOOKS = {
    "Broken Access Control": "1. Disable exposed access. 2. Review logs. 3. Reset passwords if needed.",
    "Cryptographic Failures": "1. Force password reset. 2. Redirect traffic to HTTPS. 3. Notify users of potential breach.",
    "Injection (SQLi)": "1. Block offending IP. 2. Notify dev team. 3. Initiate DB integrity check.",
    "Insecure Design": "1. Identify all exposed endpoints. 2. Remediate design flaw. 3. Add test coverage.",
    "Security Misconfiguration": "1. Revoke public access. 2. Audit configs. 3. Apply server hardening.",
    "Vulnerable and Outdated Components": "1. Patch affected systems. 2. Monitor for exploit attempts.",
    "Identification and Authentication Failures": "1. Temporarily lock account. 2. Notify user/SOC. 3. Force MFA enrollment.",
    "Software and Data Integrity Failures": "1. Remove malicious file. 2. Scan for lateral movement. 3. Block hashes.",
    "Security Logging and Monitoring Failures": "1. Enable logging. 2. Investigate all unlogged periods. 3. Deploy log integrity checks.",
    "Server-Side Request Forgery (SSRF)": "1. Block IP at WAF. 2. Audit server-side code. 3. Isolate affected resource.",
    "Port Scan": "1. Block IP/range at firewall. 2. Increase logging. 3. Alert SOC.",
    "Phishing Email": "1. Quarantine email. 2. Alert recipient. 3. Hunt for similar emails.",
    "Insider Data Exfiltration": "1. Block user. 2. Isolate endpoint. 3. Investigate other access attempts.",
    "Malware Dropper": "1. Quarantine affected endpoint. 2. Block hash at EDR. 3. Hunt for persistence.",
    "Zero-Day Ransomware": "1. Isolate all endpoints. 2. Engage IR. 3. Initiate restore from backups."
}

CAMPAIGN_STAGES = ["Recon", "Exploit", "Persistence", "Exfiltration"]

# Extended: Attacks with mapping, defense, CVEs, patch, playbook
ATTACKS = [
    {
        "name": "Broken Access Control",
        "desc": "User attempts to access admin-only endpoint without privileges",
        "vector": "HTTP",
        "payload": "GET /admin/users",
        "severity": "high"
    },
    {
        "name": "Cryptographic Failures",
        "desc": "Sensitive data sent over unencrypted channel",
        "vector": "HTTP",
        "payload": "POST /login (plaintext password)",
        "severity": "medium"
    },
    {
        "name": "Injection (SQLi)",
        "desc": "Malicious SQL injected via login form",
        "vector": "HTTP",
        "payload": "POST /login username=admin'--&password=",
        "severity": "critical"
    },
    {
        "name": "Insecure Design",
        "desc": "Missing input validation on user form",
        "vector": "HTTP",
        "payload": "POST /submit",
        "severity": "medium"
    },
    {
        "name": "Security Misconfiguration",
        "desc": "Open directory listing accessible",
        "vector": "HTTP",
        "payload": "GET /uploads/",
        "severity": "high"
    },
    {
        "name": "Vulnerable and Outdated Components",
        "desc": "Known vulnerable JS library requested",
        "vector": "HTTP",
        "payload": "GET /static/jquery-1.7.2.js",
        "severity": "medium"
    },
    {
        "name": "Identification and Authentication Failures",
        "desc": "Brute force attack on login endpoint",
        "vector": "HTTP",
        "payload": "POST /login multiple times",
        "severity": "high"
    },
    {
        "name": "Software and Data Integrity Failures",
        "desc": "Malicious dependency loaded from CDN",
        "vector": "HTTP",
        "payload": "GET /cdn/malicious-lib.js",
        "severity": "high"
    },
    {
        "name": "Security Logging and Monitoring Failures",
        "desc": "Attack evades detection (no logs generated)",
        "vector": "HTTP",
        "payload": "GET /api/stealth",
        "severity": "medium"
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "desc": "Internal resources accessed via user-supplied URL",
        "vector": "HTTP",
        "payload": "POST /fetch?url=http://169.254.169.254/latest/meta-data/",
        "severity": "critical"
    },
    {
        "name": "Port Scan",
        "desc": "Multiple SYN packets to different ports",
        "vector": "TCP",
        "payload": "SYN scan 1-1024",
        "severity": "low"
    },
    {
        "name": "Phishing Email",
        "desc": "Email with malicious link sent to user",
        "vector": "SMTP",
        "payload": f"From: {fake.email()} - Subject: Important Update",
        "severity": "medium"
    },
    {
        "name": "Insider Data Exfiltration",
        "desc": "Large file download by non-privileged user",
        "vector": "HTTP",
        "payload": "GET /confidential/finance.xlsx",
        "severity": "high"
    },
    {
        "name": "Malware Dropper",
        "desc": "Suspicious executable download detected",
        "vector": "HTTP",
        "payload": "GET /files/evil.exe",
        "severity": "critical"
    },
    {
        "name": "Zero-Day Ransomware",
        "desc": "Previously unknown ransomware deployed",
        "vector": "Email/Exploit",
        "payload": "Email attachment + lateral movement",
        "severity": "critical"
    }
]

ATTACKER_PERSONAS = [
    {
        "type": "APT Group",
        "desc": "Persistent, targeted, advanced",
        "attack_preference": ["SSRF", "Injection (SQLi)", "Malware Dropper"],
        "country": "Russia"
    },
    {
        "type": "Insider",
        "desc": "Employee with internal access",
        "attack_preference": ["Insider Data Exfiltration", "Broken Access Control"],
        "country": "USA"
    },
    {
        "type": "Script Kiddie",
        "desc": "Noisy, random attacks",
        "attack_preference": ["Port Scan", "Identification and Authentication Failures", "Phishing Email"],
        "country": "Vietnam"
    }
]

def choose_persona():
    """Randomly select an attacker persona (for campaigns/story arcs)."""
    return random.choice(ATTACKER_PERSONAS)

class AttackSimulator:
    """
    Generates attack events and campaigns for blue team/SOC simulation.
    Includes all logic for randomization, campaign simulation, and enrichment.
    """
    def __init__(self):
        self.fake = Faker()
        self.attacker_profiles = []

    def random_geolocation(self):
        """Generate a fake city/country (simulates VPN/proxy routing)."""
        # 15% chance of 'obviously mismatched' location (adds realism)
        if random.random() < 0.15:
            return {"city": self.fake.city(), "country": self.fake.country()}
        else:
            return {"city": self.fake.city(), "country": self.fake.country()}

    def random_dest_service(self):
        """Simulate random target port/service for the attack."""
        services = [
            {"port": 22, "service": "SSH"},
            {"port": 80, "service": "HTTP"},
            {"port": 443, "service": "HTTPS"},
            {"port": 3389, "service": "RDP"},
            {"port": 445, "service": "SMB"},
            {"port": 25, "service": "SMTP"},
            {"port": 3306, "service": "MySQL"},
            {"port": 5432, "service": "Postgres"},
            {"port": 8080, "service": "HTTP-Alt"}
        ]
        return random.choice(services)

    def create_attacker_profile(self, persona=None, insider=False):
        """Generate persistent attacker profile (IP, user, location) for campaign mode."""
        if persona is None:
            persona = choose_persona()
        if insider:
            location = {"city": "HQ Office", "country": persona.get("country", "USA")}
            ip = self.fake.ipv4_private()
            user = self.fake.user_name()
        else:
            location = self.random_geolocation()
            ip = self.fake.ipv4_public()
            user = self.fake.user_name()
        return {
            "ip": ip,
            "user": user,
            "location": location,
            "persona": persona
        }

    def map_attack_metadata(self, attack):
        """Add MITRE, CVEs, defense recs, patch info, playbook to each attack event."""
        name = attack["name"]
        return {
            "mitre_technique": MITRE.get(name, ""),
            "cves": CVES.get(name, []),
            "defense_recommendation": DEFENSES.get(name, ""),
            "patch_required": True if PATCHES.get(name) else False,
            "patch_instructions": PATCHES.get(name, ""),
            "playbook_step": PLAYBOOKS.get(name, "")
        }

    def attack_defense_pairing(self, attack_event):
        """
        Demo: Simulates what the defense would look like for a given attack event.
        This is used for attack-defense mapping and dashboard view.
        """
        soc_actions = [
            "Blocked by WAF", "Alert sent to SOC Analyst", "Session terminated",
            "User account disabled", "Source IP banned at firewall",
            "Email quarantined", "Endpoint isolated", "Incident escalated to Tier 2"
        ]
        return {
            "defense_timestamp": (
                datetime.strptime(attack_event['timestamp'], "%Y-%m-%d %H:%M:%S")
                + timedelta(seconds=random.randint(2, 30))
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "attack_event_id": attack_event['event_id'],
            "defense_action": random.choice(soc_actions),
            "playbook_step": attack_event.get('playbook_step', ""),
            "recommended_response": attack_event.get('defense_recommendation', ""),
            "mitre_technique": attack_event.get('mitre_technique', ""),
            "cves": attack_event.get('cves', []),
        }

    def choose_persona(self):
        """Shortcut to random persona (useful for campaigns)."""
        return random.choice(ATTACKER_PERSONAS)

    def generate_attack_event(self, attacker_profile=None, insider=False, force_attack=None, campaign_stage=None):
        """
        Generate one attack event (can be mapped to a campaign, single event, or false positive).
        Handles: true/false positive, missed log, context, all metadata for blue team demo.
        """
        attack_list = ATTACKS
        weights = [8,6,16,5,9,6,12,4,5,3,18,12,5,8,1]  # Controls how common each attack is

        # Pick attack type, optionally force a specific attack
        if force_attack:
            attack = next((a for a in attack_list if a["name"] == force_attack), None)
            if not attack:
                attack = random.choices(attack_list, weights=weights, k=1)[0]
        else:
            attack = random.choices(attack_list, weights=weights, k=1)[0]

        # Source info: real attacker or random, with possible insider
        if attacker_profile:
            source_ip = attacker_profile['ip']
            attacker_user = attacker_profile['user']
            attacker_loc = attacker_profile['location']
            persona = attacker_profile.get("persona")
        else:
            source_ip = self.fake.ipv4_private() if insider else self.fake.ipv4_public()
            attacker_user = self.fake.user_name()
            attacker_loc = self.random_geolocation()
            persona = None

        # Simulate false positives/benign events (SOC tuning/training realism)
        is_true_positive = random.random() > 0.22
        benign_reason = ""
        if not is_true_positive:
            benign_reason = random.choice([
                "Automated vulnerability scan by approved vendor",
                "Normal backup job misclassified",
                "User error flagged as suspicious",
                "Legitimate admin activity during maintenance window",
                "Known security research scanner IP",
                "Test traffic from internal red team"
            ])

        # Simulate missed logs (logs that should be there but are missing)
        is_logged = True
        missed_log_context = ""
        if attack["name"] == "Security Logging and Monitoring Failures" or random.random() < 0.08:
            is_logged = False
            missed_log_context = random.choice([
                "Log pipeline misconfiguration prevented event capture.",
                "SIEM log source offline during attack window.",
                "Critical log forwarding failed due to disk space exhaustion.",
                "Event suppression rule misapplied; SOC did not see alert.",
                "Agent crash led to no logs for 30 min."
            ])

        # Generate destination info (target host, port, service)
        dest_ip = self.fake.ipv4_private()
        dest_info = self.random_dest_service()

        # Unique event ID for tracking and correlation
        event_id = str(uuid.uuid4())
        meta = self.map_attack_metadata(attack)

        # All fields bundled into a single event dict (matches dashboard table columns)
        event = {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack["name"],
            "description": attack["desc"],
            "vector": attack["vector"],
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "dest_port": dest_info["port"],
            "dest_service": dest_info["service"],
            "payload": attack["payload"],
            "severity": attack["severity"],
            "attacker_user": attacker_user,
            "target_hostname": self.fake.hostname(),
            "city": attacker_loc['city'],
            "country": attacker_loc['country'],
            "persona": persona["type"] if persona else ("Insider" if insider else "Unknown"),
            "is_true_positive": is_true_positive,
            "benign_reason": benign_reason,
            "is_logged": is_logged,
            "missed_log_context": missed_log_context,
            "stage": campaign_stage if campaign_stage else "",
            # Metadata (MITRE, CVE, defense rec, patch, playbook)
            **meta
        }
        return event

    def generate_attack_burst(self, burst_len=4, persona=None, insider=False):
        """
        Simulate a burst of attacks (same actor/persona). Used for campaign/chained scenarios.
        """
        attacker = self.create_attacker_profile(persona=persona, insider=insider)
        burst_events = []
        for i in range(burst_len):
            stage = CAMPAIGN_STAGES[i] if i < len(CAMPAIGN_STAGES) else ""
            burst_events.append(self.generate_attack_event(attacker, insider=insider, campaign_stage=stage))
        return burst_events

    def generate_attack_campaign(self, n=10, persona=None):
        """
        Generate a campaign: a sequence of attacks tied to a single persona, staged across phases.
        """
        persona = persona or choose_persona()
        attacker = self.create_attacker_profile(persona=persona)
        events = []
        # Recon first if it's a preferred stage
        if "Port Scan" in persona.get("attack_preference", []):
            events.append(self.generate_attack_event(attacker, force_attack="Port Scan", campaign_stage="Recon"))
        # Then chain the main preferred attacks (across campaign stages)
        for idx, atk_type in enumerate(persona.get("attack_preference", [])):
            stage = CAMPAIGN_STAGES[idx+1] if idx+1 < len(CAMPAIGN_STAGES) else ""
            events.append(self.generate_attack_event(attacker, force_attack=atk_type, campaign_stage=stage))
        # Add noise/random attacks to fill out the campaign
        for _ in range(max(0, n - len(events))):
            events.append(self.generate_attack_event(attacker))
        return events

    def generate_chained_attack(self, persona=None):
        """
        Generate a story-arc attack (Recon -> Exploit -> Persistence -> Exfiltration)
        Shows an attack progressing through multiple steps/phases.
        """
        persona = persona or choose_persona()
        attacker = self.create_attacker_profile(persona=persona)
        story = []
        if "Port Scan" in persona.get("attack_preference", []):
            story.append(self.generate_attack_event(attacker, force_attack="Port Scan", campaign_stage="Recon"))
        for idx, atk in enumerate(persona.get("attack_preference", [])):
            stage = CAMPAIGN_STAGES[idx+1] if idx+1 < len(CAMPAIGN_STAGES) else ""
            story.append(self.generate_attack_event(attacker, force_attack=atk, campaign_stage=stage))
        if "Insider Data Exfiltration" in persona.get("attack_preference", []):
            story.append(self.generate_attack_event(attacker, force_attack="Insider Data Exfiltration", campaign_stage="Exfiltration"))
        return story

    def generate_mixed_activity(self, n=20):
        """
        Main event generator for dashboard/SOC feed. Creates realistic stream:
        - Majority: random attacks
        - Adds: 2-3 attack bursts (campaigns or noise)
        - Shuffles for realism (not all attacks are related)
        """
        events = []
        for _ in range(int(n * 0.6)):
            events.append(self.generate_attack_event())
        for _ in range(random.randint(2,3)):
            burst = self.generate_attack_burst(burst_len=random.randint(3,5))
            events.extend(burst)
        random.shuffle(events)
        return events

    def generate_attack_stream(self, n=20, start_time=None, avg_spacing_seconds=30):
        """
        Generates a timeline of n attacks, each spaced apart by a random interval.
        Used for plotting activity over time.
        """
        if not start_time:
            start_time = datetime.now()
        events = []
        current_time = start_time
        for event in self.generate_mixed_activity(n):
            event_time = current_time + timedelta(seconds=random.randint(avg_spacing_seconds//2, avg_spacing_seconds*2))
            event['timestamp'] = event_time.strftime("%Y-%m-%d %H:%M:%S")
            events.append(event)
            current_time = event_time
        return events

    def maybe_inject_rare_event(self, events):
        """
        Occasionally inject a rare, high-impact event (like ransomware).
        Demo: 'real life' -- sometimes serious stuff just happens!
        """
        if random.random() < 0.05:
            persona = choose_persona()
            attacker = self.create_attacker_profile(persona=persona)
            event = self.generate_attack_event(attacker, force_attack="Zero-Day Ransomware", campaign_stage="Impact")
            events.append(event)
        return events

    def generate_realistic_log(self, n=100):
        """
        Highest-level generator. Combines:
        - Mixed activity (noise, campaigns)
        - Multiple chained attacks (for story arcs)
        - Insider events, rare events, real false positives, and missed logs
        - Bundles output as a dict ready for the dashboard or analysis
        """
        logs = []
        logs.extend(self.generate_attack_stream(n=int(n*0.6)))
        for _ in range(random.randint(2, 5)):
            persona = choose_persona()
            logs.extend(self.generate_chained_attack(persona=persona))
        for _ in range(random.randint(1, 3)):
            for _ in range(random.randint(2, 4)):
                logs.append(self.generate_attack_event(insider=True))
        logs = self.maybe_inject_rare_event(logs)
        # Sort by timestamp for real-world look
        logs.sort(key=lambda x: x['timestamp'])
        # For every log that was 'logged', generate a paired defense event
        attack_defense_pairs = []
        for log in logs:
            if log['is_logged']:
                attack_defense_pairs.append(self.attack_defense_pairing(log))
        return {"attack_logs": logs, "defense_logs": attack_defense_pairs}

# Quick demo/testing: print out sample logs if run standalone
if __name__ == "__main__":
    sim = AttackSimulator()
    logs = sim.generate_realistic_log(10)
    print("=== Sample Attack Log ===")
    for event in logs["attack_logs"]:
        print(event)
    print("\n=== Sample Defense Actions ===")
    for defense in logs["defense_logs"]:
        print(defense)
