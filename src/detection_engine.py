from collections import defaultdict
from datetime import datetime, timedelta, timezone


def parse_timestamp(value):
    """Parse an ISO 8601 timestamp and normalize it to UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def detect_threats(events, failure_threshold=3, correlation_minutes=10):
    """
    Analyze normalized security events and return detection findings.

    Events are expected to contain:
    event_id, timestamp, host, username, source_ip, event_type,
    process, command_line, and details.
    """
    findings = []
    ordered_events = sorted(
        events,
        key=lambda event: parse_timestamp(event["timestamp"])
    )

    failures_by_ip = defaultdict(list)
    failures_by_account = defaultdict(list)

    for event in ordered_events:
        if event.get("event_type") == "login_failure":
            failures_by_ip[event.get("source_ip", "unknown")].append(event)
            failures_by_account[
                (event.get("username", "unknown"),
                 event.get("source_ip", "unknown"))
            ].append(event)

    window = timedelta(minutes=correlation_minutes)

        # Detection 1: repeated authentication failures within a time window.
    for source_ip, failures in failures_by_ip.items():
        start = 0

        for end, current_failure in enumerate(failures):
            current_time = parse_timestamp(current_failure["timestamp"])

            while (
                start <= end
                and current_time - parse_timestamp(
                    failures[start]["timestamp"]
                ) > window
            ):
                start += 1

            window_failures = failures[start:end + 1]

            if len(window_failures) >= failure_threshold:
                event_ids = [
                    event["event_id"] for event in window_failures
                ]

                # Avoid emitting duplicate findings for the same event set.
                if any(
                    finding["rule_id"] == "TH-001"
                    and finding["source_ip"] == source_ip
                    and finding["event_ids"] == event_ids
                    for finding in findings
                ):
                    continue

                findings.append({
                    "rule_id": "TH-001",
                    "title": "Repeated Authentication Failures",
                    "severity": "HIGH",
                    "category": "Credential Access",
                    "source_ip": source_ip,
                    "username": "multiple_or_unknown",
                    "host": "multiple_or_unknown",
                    "event_ids": event_ids,
                    "description": (
                        f"{len(window_failures)} failed logins were observed "
                        f"from {source_ip} within {correlation_minutes} "
                        "minutes."
                    ),
                    "recommendation": (
                        "Review authentication logs, identify affected "
                        "accounts, and verify whether the source is "
                        "authorized."
                    ),
                })

    # Detection 2: successful login shortly after repeated failures
    # for the same account and source IP.
    for event in ordered_events:
        if event.get("event_type") != "login_success":
            continue

        account_key = (
            event.get("username", "unknown"),
            event.get("source_ip", "unknown"),
        )
        success_time = parse_timestamp(event["timestamp"])

        related_failures = [
            failure
            for failure in failures_by_account.get(account_key, [])
            if timedelta(0) <= (
                success_time - parse_timestamp(failure["timestamp"])
            ) <= window
        ]

        if len(related_failures) >= failure_threshold:
            findings.append({
                "rule_id": "TH-002",
                "title": "Successful Login After Repeated Failures",
                "severity": "HIGH",
                "category": "Credential Access",
                "source_ip": event.get("source_ip", "unknown"),
                "username": event.get("username", "unknown"),
                "host": event.get("host", "unknown"),
                "event_ids": [
                    *(failure["event_id"] for failure in related_failures),
                    event["event_id"],
                ],
                "description": (
                    f"{event.get('username', 'Unknown user')} logged in "
                    "successfully after repeated failures from the same "
                    "source IP within the correlation window."
                ),
                "recommendation": (
                    "Verify the login with the account owner, review MFA "
                    "and session activity, and investigate related events."
                ),
            })

    # Detection 3: suspicious PowerShell command-line indicators.
    for event in ordered_events:
        if event.get("event_type") != "process_creation":
            continue

        process = event.get("process", "").lower()
        command_line = event.get("command_line", "").lower()

        indicators = [
            indicator
            for indicator in ("-encodedcommand", "-enc ")
            if indicator in command_line
        ]

        if process == "powershell.exe" and indicators:
            findings.append({
                "rule_id": "TH-003",
                "title": "Suspicious PowerShell Command Indicator",
                "severity": "MEDIUM",
                "category": "Execution",
                "source_ip": event.get("source_ip", "unknown"),
                "username": event.get("username", "unknown"),
                "host": event.get("host", "unknown"),
                "event_ids": [event["event_id"]],
                "description": (
                    "PowerShell was launched with an encoded-command "
                    "indicator. This alone does not prove malicious activity."
                ),
                "recommendation": (
                    "Inspect the original process command line, parent "
                    "process, user context, and surrounding telemetry."
                ),
            })

    # Detection 4: privilege changes requiring review.
    for event in ordered_events:
        if event.get("event_type") == "privilege_change":
            findings.append({
                "rule_id": "TH-004",
                "title": "Privilege Change Observed",
                "severity": "HIGH",
                "category": "Privilege Escalation",
                "source_ip": event.get("source_ip", "unknown"),
                "username": event.get("username", "unknown"),
                "host": event.get("host", "unknown"),
                "event_ids": [event["event_id"]],
                "description": event.get(
                    "details", "A privilege change was observed."
                ),
                "recommendation": (
                    "Verify the change was approved, identify the actor "
                    "and target group, and review nearby account activity."
                ),
            })

    return findings
