"""Normalize security events into the project's common event schema."""

from datetime import datetime, timezone


REQUIRED_FIELDS = ("timestamp", "event_type")


def _utc_timestamp(value):
    """Convert an ISO 8601 timestamp to UTC ISO format."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    else:
        raise ValueError("Event timestamp must be a non-empty ISO 8601 value")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event(event, index=1, default_source="unknown"):
    """Normalize one event while preserving additional source fields."""
    if not isinstance(event, dict):
        raise TypeError("Each event must be a dictionary")

    missing = [field for field in REQUIRED_FIELDS if not event.get(field)]
    if missing:
        raise ValueError(f"Missing required event fields: {', '.join(missing)}")

    normalized = dict(event)
    normalized["timestamp"] = _utc_timestamp(event["timestamp"])

    defaults = {
        "event_id": f"EVT-{index:04d}",
        "host": "unknown",
        "username": "unknown",
        "source_ip": "unknown",
        "process": "",
        "command_line": "",
        "details": "",
        "source": default_source,
    }

    for field, default in defaults.items():
        value = normalized.get(field)
        if value is None or value == "":
            normalized[field] = default

    normalized["event_type"] = str(normalized["event_type"]).strip().lower()
    return normalized


def normalize_events(events, default_source="unknown"):
    """Normalize a collection of events and return them chronologically."""
    if not isinstance(events, (list, tuple)):
        raise TypeError("Events must be supplied as a list or tuple")

    normalized = [
        normalize_event(event, index=index, default_source=default_source)
        for index, event in enumerate(events, start=1)
    ]

    normalized.sort(key=lambda event: datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    ))
    return normalized
