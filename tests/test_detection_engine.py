import json
from pathlib import Path

from src.detection_engine import detect_threats


DATA_FILE = Path("data/raw/sample_events.json")


def load_sample_events():
    with DATA_FILE.open(encoding="utf-8-sig") as file:
        return json.load(file)


def test_sample_dataset_generates_four_detections():
    events = load_sample_events()

    findings = detect_threats(events)

    assert len(events) == 8
    assert len(findings) == 4


def test_expected_detection_rules_are_present():
    findings = detect_threats(load_sample_events())

    rule_ids = {finding["rule_id"] for finding in findings}

    assert rule_ids == {"TH-001", "TH-002", "TH-003", "TH-004"}


def test_successful_login_finding_correlates_four_events():
    findings = detect_threats(load_sample_events())

    finding = next(
        item for item in findings if item["rule_id"] == "TH-002"
    )

    assert finding["event_ids"] == [
        "EVT-1001",
        "EVT-1002",
        "EVT-1003",
        "EVT-1004",
    ]


def test_routine_events_do_not_trigger_detections():
    events = [
        event
        for event in load_sample_events()
        if event["event_id"] in {"EVT-1007", "EVT-1008"}
    ]

    assert detect_threats(events) == []


def test_powerShell_indicator_is_medium_severity():
    findings = detect_threats(load_sample_events())

    finding = next(
        item for item in findings if item["rule_id"] == "TH-003"
    )

    assert finding["severity"] == "MEDIUM"
    assert finding["event_ids"] == ["EVT-1005"]

def test_repeated_failures_within_window_trigger_detection():
    from src.detection_engine import detect_threats

    events = [
        {
            "event_id": f"FAIL-{i}",
            "timestamp": timestamp,
            "host": "WS-TEST",
            "username": "testuser",
            "source_ip": "192.0.2.99",
            "event_type": "login_failure",
            "process": "",
            "command_line": "",
            "details": "Synthetic failed login",
        }
        for i, timestamp in enumerate(
            [
                "2026-10-20T09:00:00Z",
                "2026-10-20T09:01:00Z",
                "2026-10-20T09:02:00Z",
            ],
            start=1,
        )
    ]

    findings = detect_threats(
        events, failure_threshold=3, correlation_minutes=10
    )

    assert any(
        finding["rule_id"] == "TH-001"
        for finding in findings
    )


def test_repeated_failures_outside_window_do_not_trigger_detection():
    from src.detection_engine import detect_threats

    events = [
        {
            "event_id": f"FAIL-{i}",
            "timestamp": timestamp,
            "host": "WS-TEST",
            "username": "testuser",
            "source_ip": "192.0.2.99",
            "event_type": "login_failure",
            "process": "",
            "command_line": "",
            "details": "Synthetic failed login",
        }
        for i, timestamp in enumerate(
            [
                "2026-10-20T09:00:00Z",
                "2026-10-20T09:06:00Z",
                "2026-10-20T09:12:00Z",
            ],
            start=1,
        )
    ]

    findings = detect_threats(
        events, failure_threshold=3, correlation_minutes=10
    )

    assert not any(
        finding["rule_id"] == "TH-001"
        for finding in findings
    )