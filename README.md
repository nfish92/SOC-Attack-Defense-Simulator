SOC Attack-Defense Simulator
A hands-on, interview-ready Python/Streamlit project that simulates realistic cyber attacks, SOC defense actions, and end-to-end incident handling—all mapped to MITRE ATT&CK and the OWASP Top 10.

🚀 Overview
SOC Attack-Defense Simulator is a full-featured simulation environment for generating, visualizing, and analyzing cyber attack/defense workflows. The platform is built for blue teamers, SOC analysts, and students looking to practice real-world detection and response—without needing a live network or expensive tooling.

You get instant attack/defense event generation, replayable logs, interactive dashboards, and mapped playbooks, all in Python. Perfect for learning, demoing, or prepping for a SOC role.

⚡ Features
Attack Simulator

Generates fake but realistic security events (SQLi, phishing, ransomware, SSRF, insider threats, etc.)

All attacks mapped to MITRE ATT&CK techniques and CVEs

Supports campaign chaining, attacker personas, and both true/false positives

Defense Simulator

Maps attacks to multi-stage defense actions, recommendations, and escalation workflows

Probabilistic outcomes (not every defense is a win), with urgent escalations when appropriate

Defense playbooks and remediation guidance included for each attack

Logger Module

Logs all attack/defense events to JSONL or CSV (with log rotation)

Supports event filtering (true positives only, failed defenses only)

Allows replay of logs for dashboard visualization or retroactive analysis

Interactive Streamlit Dashboard

View attacks and mapped defenses in real time or from past logs

Incident deep dives, campaign story arcs, and metrics (blocked, escalated, avg. response time, analyst score)

Downloadable logs, escalation markers, analyst notes, and a clean, modern UI

🛠️ Installation
Clone the repo and install dependencies:

bash
Copy
Edit
git clone https://github.com/yourname/soc-attack-defense-simulator.git
cd soc-attack-defense-simulator
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
Install extra dependencies for the dashboard:

bash
Copy
Edit
pip install streamlit plotly pandas faker
▶️ Running the Dashboard
From the root of the repo:

bash
Copy
Edit
streamlit run dashboard/dashboard.py
This will launch the interactive dashboard in your browser.

Generate random attacks, view real SOC-style defense responses, explore escalations, and download logs.

📋 File Structure
attack_simulator/attack_simulator.py: Attack event generation (OWASP/MITRE/CVE mapped)

defense_simulator/defense_simulator.py: Maps attacks to realistic defense actions, escalation, recommendations

logger/logger.py: Flexible event logging and replay system

dashboard/dashboard.py: Main Streamlit UI with all dashboard logic

tests/tests.py: Pytest-style sanity checks for attack, defense, logging

💡 Example Use Cases
SOC Interview Practice: Demo incident response, detection, and log review in a live simulated environment.

Learning/Teaching: Visualize and explain how SOCs defend against the most common and most dangerous cyber threats.

Portfolio: Prove your Python, Streamlit, security, and automation skills with a practical project.

🖥️ Screenshots
(Insert dashboard screenshots or GIFs here if available)

🧩 Extending the Project
Add your own custom attacks or defense logic in attack_simulator.py or defense_simulator.py.

Integrate with SIEM APIs or ticketing systems for more realism.

Expand dashboards with more metrics or real-world log ingest.

📝 How It Works
Attack Events:
Simulate an attack using the AttackSimulator—mapped to MITRE, CVE, and attacker persona.

Defense Mapping:
Each attack is processed by DefenseSimulator to determine the outcome (blocked, escalated, failed, etc.), including recommendations and escalation flags.

Logging:
All activity is logged to disk (JSONL/CSV), supporting replay and filtering for blue team analysis.

Dashboard:
The Streamlit app ties it all together, letting you generate/replay events, review incidents, add analyst notes, and download log files for later.

📚 Project Goals
Hands-on, portfolio-ready SOC simulation for blue teamers

Realistic event flows for detection and response

Built to impress at interviews, on GitHub, or as a security training tool

🤝 Contributing
Pull requests welcome. Open an issue or PR if you’d like to contribute or spot a bug.

📄 License
MIT License