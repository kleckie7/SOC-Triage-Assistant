# SOC Triage Assistant 🛡️

**Live Demo**: [Try the app here!](https://soc-triage-assistant-dk9ifyacmb4kjcqfvpkqz9.streamlit.app/)

An automated SOC alert triage tool built with Python and Streamlit. It ingests alerts (mock or uploaded CSV/JSON), enriches with threat intel (AbuseIPDB), deduplicates/groups, scores risk (ML + rules), provides AI recommendations (Groq Llama), and supports interactive response with SLA timers and CSV export.

## Features
- Mock alert generation or CSV/JSON upload (simulates SIEM feeds)
- Real IP enrichment (AbuseIPDB) and risk scoring (ML + rules)
- AI triage suggestions (Groq Llama model)
- Deduplication, grouping, interactive close/escalate, SLA timer
- Export triaged reports as CSV
- Live mode for real-time simulation

## Why I Built This
As an aspiring SOC analyst, this automates alert triage — the #1 daily task with high volume and false positives. It reduces fatigue, speeds MTTR, and prioritizes threats.

## Run Locally
```bash
git clone https://github.com/kleckie7/SOC-Triage-Assistant.git
cd SOC-Triage-Assistant
pip install -r requirements.txt
streamlit run app.py
