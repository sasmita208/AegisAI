# evtx_to_structured.py
from Evtx.Evtx import Evtx
import lxml.etree as ET

input_file = "Security.evtx"
output_file = "structured.txt"

with Evtx(input_file) as log, open(output_file, "w", encoding="utf-8") as out:
    for record in log.records():
        xml = ET.fromstring(record.xml())

        # Extract fields safely
        event_id = xml.findtext(".//EventID", default="N/A")
        time = xml.find(".//TimeCreated").attrib.get("SystemTime", "N/A") if xml.find(".//TimeCreated") is not None else "N/A"
        user = xml.findtext(".//Data[@Name='TargetUserName']", default="N/A")
        ip = xml.findtext(".//Data[@Name='IpAddress']", default="N/A")
        logon_type = xml.findtext(".//Data[@Name='LogonType']", default="N/A")
        status = xml.findtext(".//Data[@Name='Status']", default="N/A")
        message = xml.findtext(".//Data", default="N/A")

        # Write structured event
        out.write(
            f"Time={time}, EventID={event_id}, User={user}, IP={ip}, "
            f"LogonType={logon_type}, Status={status}, Message={message}\n"
        )
