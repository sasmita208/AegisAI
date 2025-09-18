# app.py
import streamlit as st
import json
import pandas as pd
from io import StringIO
from ibm import analyze_log   # import function from ibm.py

st.set_page_config(page_title="Aegis AI Security Analyzer", layout="wide")
st.title("🛡 AegisAI: AI Security Log Analyzer")
st.write("Upload, parse, and analyze security logs with IBM Granite foundation models")

# ================================
# SECTION 1: LOG PARSING
# ================================
st.header("📂 Log Parsing (Raw → Structured CSV)")

uploaded_raw = st.file_uploader("Upload raw log file (.txt or .log)", type=["txt", "log"], key="raw")

if uploaded_raw is not None:
    raw_data = uploaded_raw.read().decode("utf-8", errors="ignore")

    try:
        # Simple parser: split by lines and commas (replace with your parser if needed)
        log_lines = [line.strip().split(",") for line in raw_data.splitlines() if line.strip()]
        df_parsed = pd.DataFrame(log_lines)

        # If at least 4 columns, rename
        if df_parsed.shape[1] >= 4:
            df_parsed = df_parsed.iloc[:, :4]
            df_parsed.columns = ["Timestamp", "Source", "Event", "Details"]

        st.success("✅ Raw logs parsed successfully!")
        st.dataframe(df_parsed.head(20))

        # Download button
        parsed_csv = df_parsed.to_csv(index=False).encode("utf-8")
        st.download_button("⬇ Download Parsed CSV", parsed_csv, "parsed_logs.csv", "text/csv")

    except Exception as e:
        st.error(f"⚠ Parsing failed: {e}")

st.markdown("---")

# ================================
# SECTION 2: LOG ANALYSIS
# ================================
st.header("🤖 Log Analysis (CSV or Paste Logs)")

analysis_mode = st.radio("Choose input method:", ["Upload CSV", "Paste Logs"], horizontal=True)

logs_to_process = None

if analysis_mode == "Upload CSV":
    uploaded_csv = st.file_uploader("Upload structured logs (CSV)", type=["csv"], key="csv")
    if uploaded_csv is not None:
        try:
            df_csv = pd.read_csv(uploaded_csv, nrows=100)  # limit for performance
            st.success(f"✅ Loaded {len(df_csv)} log entries")
            st.dataframe(df_csv.head(20))
            logs_to_process = df_csv.to_string(index=False)
        except Exception as e:
            st.error(f"⚠ Error reading CSV: {e}")

elif analysis_mode == "Paste Logs":
    user_log = st.text_area("Paste your security logs here:", height=200)
    if user_log.strip():
        logs_to_process = user_log.strip()

if st.button("🔍 Analyze Logs"):
    if logs_to_process:
        with st.spinner("Analyzing logs with IBM Granite..."):
            try:
                response = analyze_log(logs_to_process)
                st.success("✅ Analysis Complete!")

                # Show JSON
                st.subheader("📊 AI Forensic Report")
                st.json(response)

                # Download JSON
                json_bytes = json.dumps(response, indent=4).encode("utf-8")
                st.download_button("⬇ Download Forensic Report", json_bytes, "forensic_report.json", "application/json")

            except Exception as e:
                st.error(f"⚠ Error analyzing logs: {e}")
    else:
        st.warning("Please upload a CSV or paste logs first!")
