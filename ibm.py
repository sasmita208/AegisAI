# ibm.py
import os
import json
from dotenv import load_dotenv
from ibm_watson_machine_learning.foundation_models import Model

# ----------------------------
# Load environment variables
# ----------------------------
load_dotenv()

IBM_API_KEY = os.getenv("IBM_API_KEY")
IBM_PROJECT_ID = os.getenv("IBM_PROJECT_ID")
IBM_ML_URL = os.getenv("IBM_ML_URL", "https://us-south.ml.cloud.ibm.com")

if not IBM_API_KEY or not IBM_PROJECT_ID:
    raise ValueError("❌ IBM_API_KEY or IBM_PROJECT_ID not set. Check your .env file.")

# ----------------------------
# Model Parameters
# ----------------------------
GEN_PARAMS = {
    "decoding_method": "greedy",
    "max_new_tokens": 500,
    "temperature": 0.2,
}

PROMPT_TEMPLATE = """
You are a cybersecurity forensic assistant.
Analyze the following security logs and map the malicious behavior to the MITRE ATT&CK framework.

Logs:
{logs}

⚠ Instructions:
- Identify the most likely ATT&CK *tactic* (Execution, Persistence, Defense Evasion, Credential Access, Exfiltration, etc.).
- Identify the most likely ATT&CK *technique* (with Technique ID, e.g., T1003.001 - LSASS Memory).
- Extract *IOCs (Indicators of Compromise)* such as filenames, processes, IPs, hashes.
- Provide a short *description* of suspicious behavior.
- Output *valid JSON only*.

Format strictly as:
{{
  "attack_timeline": [],
  "summary": {{
    "stage": "",
    "technique": "",
    "iocs": [],
    "description": ""
  }}
}}
"""

# ----------------------------
# Model Initialization
# ----------------------------
def _init_model():
    return Model(
        model_id="ibm/granite-3-8b-instruct",
        credentials={"apikey": IBM_API_KEY, "url": IBM_ML_URL},
        project_id=IBM_PROJECT_ID,
    )

_model = _init_model()

# ----------------------------
# Log Analysis Function
# ----------------------------
def analyze_log(logs: str):
    """
    Send logs to IBM Granite for forensic analysis.
    Returns parsed JSON response (dict).
    """
    response = _model.generate(
        prompt=PROMPT_TEMPLATE.format(logs=logs),
        params=GEN_PARAMS
    )

    result_text = response["results"][0]["generated_text"]

    try:
        return json.loads(result_text)
    except Exception:
        # If not valid JSON, wrap in error response
        return {
            "error": "Model returned non-JSON output",
            "raw_output": result_text
        }
