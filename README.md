![SOC Attack-Defense Simulator Dashboard](dashboard-preview.png)

# SOC Attack-Defense Simulator

A hands-on, interview-ready Python/Streamlit project that simulates realistic cyber attacks, SOC defense actions, and end-to-end incident handling—all mapped to MITRE ATT&CK and the OWASP Top 10.

-----------------------------------------------------------------------------------------------------

## 🚀 Overview

**SOC Attack-Defense Simulator** is a full-featured environment for generating, visualizing, and analyzing cyber attack/defense workflows.  
It’s built for blue teamers, SOC analysts, and students looking to practice real-world detection and response—without needing a live network or expensive tools.

You get instant attack/defense event generation, replayable logs, interactive dashboards, and mapped playbooks, all in Python.  
Perfect for learning, demoing, or prepping for a SOC role.

-----------------------------------------------------------------------------------------------------

## ⚡ Features

### Attack Simulator
- Generates realistic security events (SQLi, phishing, ransomware, SSRF, insider threats, more)
- All attacks mapped to **MITRE ATT&CK** techniques and **CVEs**
- Supports campaign chaining, attacker personas, true/false positives, and missed log events

### Defense Simulator
- Maps attacks to realistic, multi-stage defense actions, recommendations, and escalation workflows
- Probabilistic outcomes (not every defense is a win), with urgent escalation logic
- Playbooks and remediation steps for every attack scenario

### Logger Module
- Logs all attack/defense events to **JSONL** or **CSV** (with log rotation)
- Filter by true positives or failed defenses for targeted log review
- Replay logs for dashboard visualization or retroactive analysis

### Interactive Streamlit Dashboard
- Live and replay views of all attacks/defenses
- Incident deep dive cards, campaign story arcs, escalation markers
- Metrics: blocked, escalated, average response time, analyst score
- Downloadable logs, analyst notes, and a clean modern UI

-----------------------------------------------------------------------------------------------------

## 📦 File Structure

attack_simulator/         # Attack event generation (OWASP/MITRE/CVE mapped)
defense_simulator/        # Maps attacks to defense actions and escalation
logger/                   # Logging and replay system
dashboard/                # Streamlit UI (dashboard.py)
logs/                     # Log output (ignored by .gitignore)
tests/                    # Simple test scripts
README.md
requirements.txt
.gitignore

-----------------------------------------------------------------------------------------------------

💻 Installation
Clone the repo and install dependencies:

git clone https://github.com/nfish92/soc-attack-defense-simulator.git

cd soc-attack-defense-simulator

python -m venv venv

source venv/bin/activate      # On Windows: venv\Scripts\activate

pip install -r requirements.txt

Or install core dependencies directly:

pip install streamlit pandas faker plotly

-----------------------------------------------------------------------------------------------------

▶️ Usage
Start the dashboard:

bash
Copy
Edit

streamlit run dashboard/dashboard.py

The dashboard will open in your web browser.

Generate random attack events, view mapped SOC defense responses, explore escalations, download logs, and add analyst notes.

-----------------------------------------------------------------------------------------------------

🧠 Example Use Cases
SOC Interview Prep: Practice incident response, detection, and log review in a safe, simulated environment.

Learning/Teaching: Show how blue teams defend against the most common and most dangerous cyber threats.

Portfolio: Prove your Python, Streamlit, and security automation skills with a practical, hands-on project.

-----------------------------------------------------------------------------------------------------

🔗 Extending the Project
Add custom attacks/defenses in attack_simulator.py or defense_simulator.py

Integrate SIEM APIs or ticketing systems for more realism

Expand dashboards with more metrics, analytics, or custom visualizations

-----------------------------------------------------------------------------------------------------

📝 How It Works
Attack Events:
Generated using AttackSimulator (mapped to MITRE, CVE, and persona)

Defense Mapping:
Each attack is processed by DefenseSimulator to determine outcome, recommendations, and escalation

Logging:
Activity is logged to disk (JSONL/CSV), supporting replay/filtering

Dashboard:
The Streamlit app lets you generate, replay, and review events, add notes, and download logs
