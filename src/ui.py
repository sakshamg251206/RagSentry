import streamlit as st
import requests
import pandas as pd
import json

# Setup page config
st.set_page_config(page_title="SecureRAG Auditor", page_icon="🛡️", layout="wide")

st.title("🛡️ SecureRAG Security Auditor")
st.markdown("A multi-agent auditing system testing for **Prompt Injection**, **Hallucination**, and **Data Leakage**.")

# Backend API URL
API_URL = "http://127.0.0.1:8000"

st.sidebar.header("Controls")
if st.sidebar.button("🚀 Start Full Audit", type="primary"):
    with st.spinner("Agents are currently auditing the RAG pipeline. This may take 1-3 minutes..."):
        try:
            resp = requests.post(f"{API_URL}/audit/start")
            
            if resp.status_code == 200:
                report = resp.json()
                st.session_state["report"] = report
                st.success("Audit Completed Successfully!")
            else:
                st.error(f"Error starting audit: {resp.text}")
        except requests.exceptions.ConnectionError:
            st.error("Failed to connect to backend. Is the FastAPI server running on port 8000?")

st.sidebar.markdown("---")
st.sidebar.subheader("Test Target RAG manually")
user_query = st.sidebar.text_area("Send a query to the vulnerable RAG:")
if st.sidebar.button("Send Query"):
    try:
        res = requests.post(f"{API_URL}/target/query", json={"prompt": user_query})
        if res.status_code == 200:
            st.sidebar.info(res.json()["response"])
        else:
            st.sidebar.error("Error connecting to RAG.")
    except Exception as e:
        st.sidebar.error(str(e))

# Main Dashboard Content
if "report" in st.session_state:
    report = st.session_state["report"]
    
    status_color = "green" if report["overall_status"] == "Secure" else "red" if "Critical" in report["overall_status"] else "orange"
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="Overall Vulnerability Score (out of 10)", value=f"{report['total_score']}/10")
    with col2:
        st.markdown(f"### Overall Status: **<span style='color:{status_color}'>{report['overall_status']}</span>**", unsafe_allow_html=True)
        
    st.divider()
    
    st.header("🕵️‍♂️ Detailed Audit Findings")
    
    if "findings" in report and report["findings"]:
        df = pd.DataFrame(report["findings"])
        # Chart
        st.subheader("Vulnerability Severity Breakdown")
        st.bar_chart(df.set_index("vulnerability_type")["score"])
        
        st.subheader("Agent Logs & Reasons")
        for finding in report["findings"]:
            with st.expander(f"{finding['vulnerability_type']} - Score: {finding['score']}/10 ({finding['severity']})"):
                st.markdown(f"**Reasoning:** {finding['reasoning']}")
                if finding.get('successful_attack_prompt'):
                    st.code(f"Attack Prompt:\n{finding['successful_attack_prompt']}")
                st.markdown(f"**Recommended Fix:** {finding['recommended_fix']}")
    else:
        st.info("No findings recorded. Check logs.")
else:
    st.info("Click 'Start Full Audit' in the sidebar to begin the multi-agent penetration test.")
