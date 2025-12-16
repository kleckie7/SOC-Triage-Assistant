import streamlit as st
import pandas as pd
import requests
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
from groq import Groq
import json
import random

# === API KEYS (replace with your own) ===

ABUSEIPDB_API_KEY = 'your_abuseipdb_key_here'
VIRUSTOTAL_API_KEY = 'your_virustotal_key_here'
GROQ_API_KEY = 'your_groq_key_here'

# === Mock Alert Generator ===
def generate_mock_alerts(num=10):
    types = ['brute_force', 'phishing', 'malware', 'anomaly']
    severities = ['low', 'medium', 'high']
    alerts = []
    for i in range(num):
        alerts.append({
            'id': i + 1,
            'type': random.choice(types),
            'ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'severity': random.choice(severities),
            'timestamp': datetime.now().isoformat(),
            'details': 'Sample alert details'
        })
    return pd.DataFrame(alerts)

# === Enrichment ===
def enrich_alert(alert):
    ip = alert['ip']
    alert['abuse_score'] = 0
    alert['vt_malicious'] = random.randint(0, 10)  # Simulated VT result

    if ABUSEIPDB_API_KEY != 'your_abuseipdb_key_here':
        try:
            resp = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                alert['abuse_score'] = data.get('abuseConfidenceScore', 0)
        except:
            pass
    return alert

# === Processing & Grouping ===
def process_alerts(df):
    if df.empty:
        return df
    
    df = df.drop_duplicates(subset=['ip', 'type'])
    grouped = df.groupby(['type', 'severity']).size().reset_index(name='count')
    df = df.merge(grouped, on=['type', 'severity'], how='left')
    df['count'] = df['count'].fillna(1).astype(int)
    return df

# === Risk Scoring ===
def score_risks(df):
    df['risk_score'] = 'low'  # default

    required = ['abuse_score', 'vt_malicious', 'count']
    if all(col in df.columns for col in required) and len(df) > 0:  # Fixed: integer 0 and added :
        features = df[required].fillna(0)
        if len(features) >= 1:
            try:
                model = IsolationForest(contamination=0.1, random_state=42)
                preds = model.fit_predict(features)
                df['risk_score'] = ['high' if p == -1 else 'low' for p in preds]
            except:
                pass

    # Rule-based fallback
    df['risk_score'] = df.apply(
        lambda r: 'high' if (r.get('abuse_score', 0) > 50 or r.get('vt_malicious', 0) > 3) else 'low',
        axis=1
    )
    return df

# === AI Triage ===
def ai_triage(alert_dict, client=None):
    if not GROQ_API_KEY or GROQ_API_KEY == 'your_groq_key_here':
        severity = alert_dict.get('severity', 'medium')
        return "Rule-based fallback: " + ("Escalate immediately" if severity == 'high' else "Review recommended")

    if client is None:
        client = Groq(api_key=GROQ_API_KEY)

    prompt = f"""
    You are a SOC analyst. Analyze this security alert and give a short recommendation.
    Alert: {json.dumps(alert_dict, indent=2)}
    Answer in 1-2 sentences: Is this likely a true positive? Recommended action (close, escalate, block, investigate)?
    """
    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama3-8b-8192",
            temperature=0.3,
            max_tokens=200
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI failed: {str(e)}. Manual review needed."

# === Main App ===
def main():
    st.set_page_config(page_title="SOC Triage Assistant", layout="wide")
    st.title("🛡️ SOC Triage Assistant")

    # Sidebar controls
    st.sidebar.header("Alert Controls")
    source = st.sidebar.radio("Alert Source", ["Mock Simulation", "Upload File"])

    if source == "Mock Simulation":
        num = st.sidebar.slider("Number of alerts", 5, 100, 20)
        if st.sidebar.button("Generate Mock Alerts"):
            with st.spinner("Generating alerts..."):
                st.session_state.alerts = generate_mock_alerts(num)
            st.rerun()

    else:
        uploaded = st.sidebar.file_uploader("Upload CSV or JSON alerts", type=["csv", "json"])
        if uploaded:
            with st.spinner("Loading file..."):
                if uploaded.name.endswith('.csv'):
                    st.session_state.alerts = pd.read_csv(uploaded)
                else:
                    st.session_state.alerts = pd.read_json(uploaded)
            st.rerun()

    # Live Mode
    if st.sidebar.checkbox("Live Mode (add 3 alerts every 30s)"):
        placeholder = st.sidebar.empty()
        placeholder.info("Live mode active — new alerts in 30s...")
        time.sleep(30)
        new = generate_mock_alerts(3)
        if 'alerts' in st.session_state:
            st.session_state.alerts = pd.concat([st.session_state.alerts, new], ignore_index=True)
        else:
            st.session_state.alerts = new
        placeholder.empty()
        st.rerun()

    # No alerts yet
    if 'alerts' not in st.session_state or st.session_state.alerts.empty:
        st.info("👈 Use the sidebar to generate mock alerts or upload a file to start triaging.")
        st.markdown("This tool automates enrichment, deduplication, risk scoring, and AI suggestions to speed up SOC alert triage.")
        return

    # Process alerts
    df = st.session_state.alerts.copy()

    with st.spinner("Enriching alerts..."):
        df = df.apply(enrich_alert, axis=1)

    df = process_alerts(df)
    df = score_risks(df)

    with st.spinner("Getting AI recommendations..."):
        client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY and GROQ_API_KEY != 'your_groq_key_here' else None
        suggestions = [ai_triage(row.to_dict(), client) for _, row in df.iterrows()]
        df['ai_suggestion'] = suggestions

    # Display table
    st.header(f"Triaged Alerts ({len(df)} total)")
    styled = df.style.background_gradient(subset=['abuse_score'], cmap='Reds')\
                     .background_gradient(subset=['vt_malicious'], cmap='Oranges')
    st.dataframe(styled, use_container_width=True)

    # Detailed triage
    if 'id' in df.columns:
        selected = st.selectbox("Select alert for detailed triage", df['id'])
        alert = df[df['id'] == selected].iloc[0]

        st.subheader("Alert Details")
        st.json(alert.to_dict(), expanded=False)

        st.write("**AI Recommendation:**")
        st.info(alert['ai_suggestion'])

        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Auto-Close (Low Risk)"):
                st.success("Alert closed as false positive.")
        with col2:
            if st.button("🚨 Escalate to Tier 2"):
                st.warning("Alert escalated for deeper investigation.")

        st.write("**15-minute SLA Timer** (demo runs in ~10 seconds)")
        progress = st.progress(0)
        for i in range(100):
            time.sleep(0.1)
            progress.progress(i + 1)
        st.error("⏰ SLA Expired — Immediate action required!")

    # Export
    if st.button("Export Triaged Report"):
        csv = df.to_csv(index=False)
        st.download_button("Download CSV Report", csv, "soc_triage_report.csv", "text/csv")

if __name__ == "__main__":
    if 'alerts' not in st.session_state:
        st.session_state.alerts = pd.DataFrame()
    main()