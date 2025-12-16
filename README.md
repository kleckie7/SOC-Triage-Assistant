# SOC Triage Assistant 🛡️

**Live Demo**: [Try the app here!](https://soc-triage-assistant-dk9ifyacmb4kjcqfvpkqz9.streamlit.app/)

An automated SOC alert triage tool built with Python and Streamlit. It ingests alerts (mock or uploaded CSV/JSON), enriches with threat intel (AbuseIPDB), deduplicates/groups, scores risk (ML + rules), provides AI recommendations (Groq Llama), and supports interactive response with SLA timers and CSV export.

## Features
- Mock alert generation or real SIEM CSV upload
- Real-time IP enrichment and anomaly-based risk scoring
- AI-powered triage suggestions
- Live mode for continuous simulation
- Export triaged reports

## Why I Built This
As an aspiring SOC analyst, I created this to automate the most time-consuming task: triaging high-volume alerts (often 70–90% false positives). It demonstrates skills in automation, threat intel integration, and reducing analyst fatigue — key for Tier 1/2 roles.

## How to Run Locally
```bash
git clone https://github.com/kleckie7/SOC-Triage-Assistant.git
cd SOC-Triage-Assistant
pip install -r requirements.txt
streamlit run app.py
