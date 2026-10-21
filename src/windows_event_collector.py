
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "data" / "normalized" / "windows_process_events.json"

EVENT_NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def read_event_data(xml_text):
    """Parse Windows Event XML into a dictionary of event fields."""
    root = ET.fromstring(xml_text)
    system = root.find("e:System", EVENT_NAMESPACE)
    event_data = root.find("e:EventData", EVENT_NAMESPACE)

    fields = {}
    if event_data is not None:
        for item in event_data.findall("e:Data", EVENT_NAMESPACE):
            fields[item.attrib.get("Name", "")] = item.text or ""

    timestamp = system.find("e:TimeCreated", EVENT_NAMESPACE).attrib["SystemTime"]
    record_id = system.findtext("e:EventRecordID", default="unknown", namespaces=EVENT_NAMESPACE)
    computer = system.findtext("e:Computer", default="unknown", namespaces=EVENT_NAMESPACE)

    return {
        "event_id": f"WIN-{record_id}",
        "timestamp": timestamp,
        "host": computer,
        "username": "\\".join(
            value for value in (
                fields.get("SubjectDomainName", ""),
                fields.get("SubjectUserName", ""),
            )
            if value and value != "-"
        ) or "unknown",
        "source_ip": "unknown",
        "event_type": "process_creation",
        "process": Path(
            fields.get("NewProcessName", "").replace("\\", "/")
        ).name or "unknown",
        "command_line": fields.get("CommandLine", ""),
        "details": (
            "Parent process: "
            + (fields.get("ParentProcessName", "") or "unknown")
        ),
        "source": "windows_security",
        "windows_event_id": 4688,
    }


def collect_process_events(limit=100):
    """Read recent Windows Security process-creation events via PowerShell."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")

    ps_script = (
        "$ErrorActionPreference = 'Stop'; "
        f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688}} "
        f"-MaxEvents {limit} | "
        "ForEach-Object { $_.ToXml() } | "
        "ConvertTo-Json -Compress"
    )

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    if result.returncode != 0:
        message = result.stderr.strip() or "Windows event collection failed."
        raise RuntimeError(
            f"{message}\nRun this collector from an elevated PowerShell window."
        )

    output = result.stdout.strip()
    if not output:
        return []

    xml_events = json.loads(output)
    if isinstance(xml_events, str):
        xml_events = [xml_events]

    return [read_event_data(xml) for xml in xml_events]


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = collect_process_events(limit=100)
    OUTPUT_FILE.write_text(
        json.dumps(events, indent=2),
        encoding="utf-8",
    )

    print(f"Windows process events collected: {len(events)}")
    print(f"Output file: {OUTPUT_FILE}")
    print("Collection is read-only; Windows event logs were not modified.")

    if events:
        print(f"Most recent event timestamp: {events[0]['timestamp']}")
        print(f"Example process: {events[0]['process']}")


if __name__ == "__main__":
    main()
