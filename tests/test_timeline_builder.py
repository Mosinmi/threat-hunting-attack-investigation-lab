import json
from pathlib import Path

from src.detection_engine import detect_threats
from src.timeline_builder import build_timeline


DATA_FILE = Path("data/raw/sample_events.json")


def load_events():
    with DATA_FILE.open(encoding="utf-8-sig") as file:
        return json.load(file)


def test_timeline_contains_all_events():
    events = load_events()

    assert len(build_timeline(events)) == 8


def test_timeline_is_chronological():
    timeline = build_timeline(load_events())

    timestamps = [event["timestamp"] for event in timeline]

    assert timestamps == sorted(timestamps)


def test_detection_rules_are_attached_to_related_events():
    events = load_events()
    findings = detect_threats(events)

    timeline = build_timeline(events, findings)
    by_id = {event["event_id"]: event for event in timeline}

    assert "TH-001" in by_id["EVT-1001"]["detection_rules"]
    assert "TH-002" in by_id["EVT-1004"]["detection_rules"]
    assert "TH-003" in by_id["EVT-1005"]["detection_rules"]
    assert "TH-004" in by_id["EVT-1006"]["detection_rules"]


def test_routine_event_has_no_detection_rules():
    timeline = build_timeline(load_events())
    by_id = {event["event_id"]: event for event in timeline}

    assert by_id["EVT-1007"]["detection_rules"] == []


def test_timeline_does_not_modify_input_events():
    events = load_events()
    original_keys = set(events[0].keys())

    build_timeline(events, detect_threats(events))

    assert set(events[0].keys()) == original_keys
