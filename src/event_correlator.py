"""Utilities for correlating related security events."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone


def _parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def correlate_events(events, window_minutes=10):
    """
    Group events sharing a host or username when they occur within
    the specified time window.

    Returns groups containing the correlation key, events, and time range.
    Events with no meaningful host or username are not grouped by that key.
    """
    if window_minutes < 0:
        raise ValueError("window_minutes must be zero or greater")

    groups = []
    dimensions = ("host", "username")

    for dimension in dimensions:
        buckets = defaultdict(list)

        for event in events:
            value = event.get(dimension)
            if value and str(value).strip().lower() != "unknown":
                buckets[str(value)].append(event)

        for value, matching_events in buckets.items():
            ordered = sorted(
                matching_events,
                key=lambda event: _parse_timestamp(event["timestamp"])
            )

            current_group = []
            group_start = None

            for event in ordered:
                event_time = _parse_timestamp(event["timestamp"])

                if (
                    current_group
                    and event_time - group_start
                    > timedelta(minutes=window_minutes)
                ):
                    if len(current_group) > 1:
                        groups.append({
                            "correlation_field": dimension,
                            "correlation_value": value,
                            "start_time": current_group[0]["timestamp"],
                            "end_time": current_group[-1]["timestamp"],
                            "event_ids": [
                                item.get("event_id", "") for item in current_group
                            ],
                            "events": current_group,
                        })

                    current_group = []
                    group_start = None

                if not current_group:
                    group_start = event_time

                current_group.append(event)

            if len(current_group) > 1:
                groups.append({
                    "correlation_field": dimension,
                    "correlation_value": value,
                    "start_time": current_group[0]["timestamp"],
                    "end_time": current_group[-1]["timestamp"],
                    "event_ids": [
                        item.get("event_id", "") for item in current_group
                    ],
                    "events": current_group,
                })

    return sorted(groups, key=lambda group: group["start_time"])
