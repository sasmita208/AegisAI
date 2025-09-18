import csv
import re
from datetime import datetime
from pathlib import Path

# Regex patterns
timestamp_patterns = [
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",   # Jan 12 08:32:15
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",   # 2023-01-12 08:32:15
]
ip_pattern = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
port_pattern = r"port\s+(?P<port>\d+)"
pid_pattern = r"\[(?P<pid>\d+)\]"

def extract_timestamp(text):
    for pattern in timestamp_patterns:
        match = re.search(pattern, text)
        if match:
            ts = match.group("timestamp")
            for fmt in ["%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                try:
                    parsed = datetime.strptime(ts, fmt)
                    return parsed.isoformat()
                except ValueError:
                    continue
            return ts
    return ""

def extract_fields(text):
    return {
        "timestamp": extract_timestamp(text),
        "ip": re.search(ip_pattern, text).group("ip") if re.search(ip_pattern, text) else "",
        "port": re.search(port_pattern, text).group("port") if re.search(port_pattern, text) else "",
        "pid": re.search(pid_pattern, text).group("pid") if re.search(pid_pattern, text) else "",
        "message": text.strip()
    }

def process_csv(input_file, output_writer):
    with open(input_file, newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        # Check if there's a 'message' column, otherwise combine all columns
        for row in reader:
            message = row.get("message") or " ".join(row.values())
            fields = extract_fields(message)
            output_writer.writerow(fields)

def process_txt(input_file, output_writer):
    with open(input_file, encoding='utf-8') as infile:
        for line in infile:
            fields = extract_fields(line)
            output_writer.writerow(fields)

def process_all(input_folder, output_file):
    log_dir = Path(input_folder)
    with open(output_file, "w", newline='', encoding='utf-8') as outfile:
        fieldnames = ["timestamp", "ip", "port", "pid", "message"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for file_path in log_dir.glob("*"):
            if file_path.suffix.lower() == ".csv":
                print(f"Processing CSV: {file_path}")
                process_csv(file_path, writer)
            elif file_path.suffix.lower() == ".txt":
                print(f"Processing TXT: {file_path}")
                process_txt(file_path, writer)
            else:
                print(f"Skipping unsupported file: {file_path}")

# Run parser
process_all("logs", "parsed_logs.csv")
import re
import csv
from datetime import datetime

timestamp_patterns = [
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",  # Jan 12 08:32:15
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",  # 2023-01-12 08:32:15
]

ip_pattern = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
port_pattern = r"port\s+(?P<port>\d+)"
pid_pattern = r"\[(?P<pid>\d+)\]"

def extract_timestamp(line: str):
    for pattern in timestamp_patterns:
        match = re.search(pattern, line)
        if match:
            ts = match.group("timestamp")
            for fmt in ["%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                try:
                    parsed = datetime.strptime(ts, fmt)
                    return parsed.isoformat()
                except Exception:
                    continue
            return ts
    return ""

def parse_log_line(line: str):
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

    host_match = re.search(r"host=([\w\.-]+)", line)
    if host_match:
        data["host"] = host_match.group(1)

    service_match = re.search(r"(\w+)\[(\d+)\]", line)
    if service_match:
        data["service"] = service_match.group(1)
        data["pid"] = service_match.group(2)
    else:
        pid_match = re.search(pid_pattern, line)
        if pid_match:
            data["pid"] = pid_match.group("pid")

    ip_match = re.search(ip_pattern, line)
    if ip_match:
        data["ip"] = ip_match.group("ip")

    port_match = re.search(port_pattern, line)
    if port_match:
        data["port"] = port_match.group("port")

    if ":" in line:
        parts = line.split(":", 1)
        message = parts[1].strip()
        tokens = message.split()
        if len(tokens) > 1:
            data["alert"] = tokens[0] + (" " + tokens[1] if tokens[1].islower() else "")
            data["reason"] = message[len(data["alert"]):].strip()
        else:
            data["alert"] = tokens[0]
            data["reason"] = message

    return data

def parse_logs_to_structured(lines):
    return [parse_log_line(line) for line in lines if line.strip()]

def save_to_csv(parsed_logs, filename="structured_logs.csv"):
    if not parsed_logs:
        return
    keys = parsed_logs[0].keys()
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(parsed_logs)

def process_uploaded_logs(input_file="consolidated_data.csv", output_file="output.csv"):
    lines = []

    try:
        with open(input_file, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                for cell in row:
                    if cell.strip():
                        lines.append(cell.strip())
    except FileNotFoundError:
        print(f"No '{input_file}' file found.")
        return None

    structured = parse_logs_to_structured(lines)
    save_to_csv(structured, output_file)
    return output_file

if __name__ == "__main__":
    input_file = "consolidated_data.csv"
    output_file = "output.csv"

    result = process_uploaded_logs(input_file, output_file)
    if result:
        print(f"Logs parsed and saved to {output_file}")
    else:
        print("No log data to parse.")
