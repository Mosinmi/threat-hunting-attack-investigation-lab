import json
from src.detection_engine import detect_threats
from src.timeline_builder import build_timeline

with open("data/raw/sample_events.json", encoding="utf-8-sig") as file:
    events = json.load(file)

findings = detect_threats(events)
timeline = build_timeline(events, findings)

print(f"Timeline events: {len(timeline)}")
print("-" * 85)

for event in timeline:
    rules = ", ".join(event["detection_rules"]) or "No detection"
    print(
        f"{event['timestamp']} | {event['host']} | "
        f"{event['username']} | {event['event_type']} | {rules}"
    )
