import json
from src.detection_engine import detect_threats

with open("data/raw/sample_events.json", encoding="utf-8-sig") as file:
    events = json.load(file)

findings = detect_threats(events)

print(f"Events analyzed: {len(events)}")
print(f"Detections: {len(findings)}")

for finding in findings:
    event_ids = ", ".join(finding["event_ids"])
    print(
        f"[{finding['severity']}] "
        f"{finding['rule_id']} - {finding['title']} "
        f"| Events: {event_ids}"
    )
