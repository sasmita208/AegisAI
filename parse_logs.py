import os
import re
import pandas as pd
from datetime import datetime

# Regex patterns
timestamp_patterns = [
    r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",  # 2023-08-01 12:34:56
    r"\b\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\b",     # 01/08/2023 12:34:56
]
ip_pattern = r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)"
port_pattern = r"port=(?P<port>\d+)"
pid_pattern = r"pid=(?P<pid>\d+)"

# Extract timestamp
def extract_timestamp(line: str):
    for pattern in timestamp_patterns:
        match = re.search(pattern, line)
        if match:
            return match.group()
    return ""

# Parse a single log line
def parse_log_line(line: str):
    """Parse a single log line into structured fields"""
    data = {
        "timestamp": extract_timestamp(line),
        "host": "",
        "service": "",
        "pid": "",
        "ip": "",
        "port": "",
        "alert": "",
        "reason": "",
        "message": line.strip()
    }

    # Host
    host_match = re.search(r"host=([\w\.-]+)", line)
    if host_match:
        data["host"] = host_match.group(1)

    # Service + PID
    service_match = re.search(r"(\w+)\[(\d+)\]", line)
    if service_match:
        data["service"] = service_match.group(1)
        data["pid"] = service_match.group(2)
    else:
        pid_match = re.search(pid_pattern, line)
        if pid_match:
            data["pid"] = pid_match.group("pid")

    # IP
    ip_match = re.search(ip_pattern, line)
    if ip_match:
        data["ip"] = ip_match.group("ip")

    # Port
    port_match = re.search(port_pattern, line)
    if port_match:
        data["port"] = port_match.group("port")

    # Alert + Reason
    if ":" in line:
        parts = line.split(":", 1)
        message = parts[1].strip()
        if message:  # Only proceed if there's something after ':'
            tokens = message.split()
            if len(tokens) > 1:
                data["alert"] = tokens[0] + (" " + tokens[1] if tokens[1].islower() else "")
                data["reason"] = message[len(data["alert"]):].strip()
            elif len(tokens) == 1:
                data["alert"] = tokens[0]
                data["reason"] = ""
        else:
            data["alert"] = ""
            data["reason"] = ""

    return data

# Convert lines to structured format
def parse_logs_to_structured(lines):
    return [parse_log_line(line) for line in lines if line.strip()]

# Process a single file
def process_file(file_path):
    print(f"Processing: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"❌ Could not read {file_path}: {e}")
        return pd.DataFrame()

    structured = parse_logs_to_structured(lines)
    return pd.DataFrame(structured)

# Process entire folder
def process_folder(folder_path):
    all_dfs = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            df = process_file(file_path)
            if not df.empty:
                all_dfs.append(df)

    if all_dfs:
        combined_df = pd.concat(all_dfs, ignore_index=True)
    else:
        combined_df = pd.DataFrame()

    return combined_df

# ✅ MAIN EXECUTION
if __name__ == "__main__":
    folder_path = os.path.expanduser("~/hackverse/AegisAI/logs_folder")
    combined_df = process_folder(folder_path)

    print(f"\nTotal rows parsed: {len(combined_df)}")
    print(combined_df.head())

    output_file = os.path.join(os.path.dirname(__file__), "parsed_logs.csv")
    combined_df.to_csv(output_file, index=False)
    print(f"✅ All logs parsed and saved to {output_file}")
