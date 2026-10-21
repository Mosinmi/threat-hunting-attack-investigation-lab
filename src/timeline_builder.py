from datetime import datetime, timezone


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_timeline(events, findings=None):
    """Return chronological events annotated with matching detection rules."""
    findings = findings or []

    event_to_rules = {}

    for finding in findings:
        for event_id in finding.get("event_ids", []):
            event_to_rules.setdefault(event_id, []).append(
                finding["rule_id"]
            )

    timeline = []

    for event in events:
        timeline.append({
            **event,
            "detection_rules": event_to_rules.get(
                event.get("event_id", ""), []
            ),
        })

    timeline.sort(key=lambda item: parse_timestamp(item["timestamp"]))

    return timeline
