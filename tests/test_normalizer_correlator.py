import pytest

from src.log_normalizer import normalize_event, normalize_events
from src.event_correlator import correlate_events


def sample_event(event_id, timestamp, host="WS-001", username="jdoe"):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "host": host,
        "username": username,
        "event_type": "login_failure",
        "source": "synthetic",
    }


def test_normalize_event_converts_timestamp_to_utc():
    event = sample_event("E1", "2026-10-21T09:00:00+01:00")

    result = normalize_event(event)

    assert result["timestamp"] == "2026-10-21T08:00:00Z"


def test_normalize_event_supplies_optional_defaults():
    event = {
        "timestamp": "2026-10-21T08:00:00Z",
        "event_type": "LOGIN_FAILURE",
    }

    result = normalize_event(event, index=3)

    assert result["event_id"] == "EVT-0003"
    assert result["host"] == "unknown"
    assert result["source_ip"] == "unknown"
    assert result["event_type"] == "login_failure"


def test_normalize_event_rejects_missing_required_fields():
    with pytest.raises(ValueError):
        normalize_event({"event_type": "login_failure"})


def test_normalize_events_sorts_chronologically():
    events = [
        sample_event("E2", "2026-10-21T08:05:00Z"),
        sample_event("E1", "2026-10-21T08:00:00Z"),
    ]

    result = normalize_events(events)

    assert [event["event_id"] for event in result] == ["E1", "E2"]


def test_correlator_groups_events_by_host_and_username():
    events = [
        sample_event("E1", "2026-10-21T08:00:00Z"),
        sample_event("E2", "2026-10-21T08:03:00Z"),
    ]

    result = correlate_events(events, window_minutes=10)

    assert len(result) == 2
    assert {group["correlation_field"] for group in result} == {
        "host", "username"
    }
    assert all(group["event_ids"] == ["E1", "E2"] for group in result)


def test_correlator_rejects_negative_window():
    with pytest.raises(ValueError):
        correlate_events([], window_minutes=-1)


def test_correlator_ignores_single_event_groups():
    events = [sample_event("E1", "2026-10-21T08:00:00Z")]

    assert correlate_events(events) == []
