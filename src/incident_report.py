
"""Generate Markdown incident investigation reports from lab telemetry."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from src.detection_engine import detect_threats
from src.timeline_builder import build_timeline


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_FILES = {
    "synthetic": PROJECT_ROOT / "data" / "raw" / "sample_events.json",
    "windows": (
        PROJECT_ROOT / "data" / "normalized" / "windows_process_events.json"
    ),
}


def load_events(source):
    """Load events from the selected telemetry source."""
    path = DATA_FILES[source]

    if not path.exists():
        raise FileNotFoundError(
            f"Telemetry file not found: {path}. "
            "Run the Windows event collector first if using Windows mode."
        )

    with path.open(encoding="utf-8-sig") as file:
        data = json.load(file)

    return data if isinstance(data, list) else [data]


def markdown_table(rows, columns):
    """Format rows as a Markdown table."""
    if not rows:
        return "_No records available._"

    def clean(value):
        value = str(value if value not in (None, "") else "Not available")
        return value.replace("|", "\\|").replace("\n", " ")

    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"
    body = [
        "| " + " | ".join(clean(row.get(col)) for col in columns) + " |"
        for row in rows
    ]
    return "\n".join([header, separator, *body])


def generate_report(events, findings, source):
    """Build a report containing findings, evidence, and timeline."""
    timeline = build_timeline(events, findings)
    high_count = sum(f.get("severity") == "HIGH" for f in findings)
    medium_count = sum(f.get("severity") == "MEDIUM" for f in findings)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    source_label = (
        "Synthetic lab telemetry"
        if source == "synthetic"
        else "Locally collected Windows Security telemetry"
    )

    lines = [
        "# Threat Hunting & Attack Investigation Report",
        "",
        f"- **Generated:** {generated_at}",
        f"- **Data source:** {source_label}",
        f"- **Events analyzed:** {len(events)}",
        f"- **Findings generated:** {len(findings)}",
        f"- **High severity findings:** {high_count}",
        f"- **Medium severity findings:** {medium_count}",
        "",
        "## 1. Executive Summary",
        "",
    ]

    if findings:
        lines.append(
            f"The detection engine generated **{len(findings)} finding(s)** "
            f"from {len(events)} event(s). These findings require validation "
            "and are not, by themselves, proof of compromise."
        )
    else:
        lines.append(
            f"The detection engine generated no findings from {len(events)} "
            "event(s). This does **not** prove the environment is free of "
            "threats; available telemetry and detection coverage are limited."
        )

    if source == "windows":
        missing_cmd = sum(
            not event.get("command_line") for event in events
        )
        lines.extend([
            "",
            "### Windows Telemetry Limitations",
            "",
            f"- Events with no command line: {missing_cmd} of {len(events)}.",
            "- This collection contains process-creation telemetry.",
            "- Authentication detections require suitable authentication events.",
            "- Missing fields must not be interpreted as evidence of maliciousness.",
        ])

    lines.extend(["", "## 2. Detection Findings", ""])

    if not findings:
        lines.append("_No detection rules matched this dataset._")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {index}. {finding.get('title', 'Untitled finding')}",
                "",
                f"- **Rule ID:** {finding.get('rule_id', 'N/A')}",
                f"- **Severity:** {finding.get('severity', 'N/A')}",
                f"- **Category:** {finding.get('category', 'N/A')}",
                f"- **Host:** {finding.get('host', 'N/A')}",
                f"- **Username:** {finding.get('username', 'N/A')}",
                f"- **Source IP:** {finding.get('source_ip', 'N/A')}",
                f"- **Related event IDs:** "
                f"{', '.join(finding.get('event_ids', [])) or 'N/A'}",
                "",
                f"**Detection rationale:** "
                f"{finding.get('description', 'No description provided.')}",
                "",
                f"**Recommended investigation:** "
                f"{finding.get('recommendation', 'Review related evidence.')}",
                "",
            ])

    lines.extend([
        "## 3. Evidence and Event Timeline",
        "",
    ])

    timeline_rows = []
    for event in timeline:
        rules = event.get("detection_rules", [])
        if isinstance(rules, list):
            rules = ", ".join(rules) if rules else "None"

        timeline_rows.append({
            "timestamp": event.get("timestamp"),
            "event_id": event.get("event_id"),
            "host": event.get("host"),
            "username": event.get("username"),
            "event_type": event.get("event_type"),
            "process": event.get("process"),
            "detection_rules": rules,
        })

    lines.extend([
        markdown_table(
            timeline_rows,
            [
                "timestamp", "event_id", "host", "username",
                "event_type", "process", "detection_rules",
            ],
        ),
        "",
        "## 4. Investigation Priorities",
        "",
        "1. Validate the finding against the original event and surrounding logs.",
        "2. Confirm whether the activity was expected and authorized.",
        "3. Correlate relevant account, host, process, and network evidence.",
        "4. Record the analyst's conclusion and supporting evidence.",
        "5. Escalate confirmed or high-impact suspicious activity according to "
        "the organization's incident-response procedure.",
        "",
        "## 5. Scope and Safety",
        "",
        "- Findings are leads for investigation, not proof of compromise.",
        "- No containment, account changes, or other live response actions "
        "were performed by this report generator.",
        "- Conclusions are limited by the fields and events available in "
        "the selected dataset.",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a threat-hunting investigation report."
    )
    parser.add_argument(
        "--source",
        choices=sorted(DATA_FILES),
        default="synthetic",
        help="Telemetry source to analyze (default: synthetic).",
    )
    args = parser.parse_args()

    events = load_events(args.source)
    findings = detect_threats(events)
    report = generate_report(events, findings, args.source)

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / f"incident_report_{args.source}.md"
    output_path.write_text(report, encoding="utf-8")

    print(f"Telemetry source: {args.source}")
    print(f"Events analyzed: {len(events)}")
    print(f"Findings generated: {len(findings)}")
    print(f"Report saved: {output_path}")
    print("Report generation completed. No response actions were performed.")


if __name__ == "__main__":
    main()
