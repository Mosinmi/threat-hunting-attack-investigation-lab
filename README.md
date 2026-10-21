# Threat Hunting & Attack Investigation Lab

A hands-on cybersecurity portfolio project focused on threat hunting, event correlation, detection engineering, investigation timelines, and automated incident reporting using Python and Streamlit.

The lab combines a controlled synthetic dataset with locally collected Windows Security telemetry to demonstrate how an analyst can identify suspicious patterns, investigate detection results, and document findings.

## Project Objectives

- Develop detection logic for suspicious authentication and process activity.
- Correlate related security events into investigation findings.
- Build chronological timelines for incident investigation.
- Collect and normalize local Windows process-creation events.
- Generate Markdown investigation reports automatically.
- Present telemetry and findings through an interactive dashboard.
- Validate detection and timeline functionality with automated tests.

## Key Features

- **Detection engine:** identifies selected suspicious patterns using configurable detection rules.
- **Event correlation:** links related events to support investigation.
- **Investigation timeline:** organizes events chronologically and associates matching detection rules.
- **Windows telemetry collection:** collects locally available Windows process-creation events.
- **Automated reporting:** creates Markdown reports containing findings, evidence, investigation priorities, and limitations.
- **Interactive dashboard:** explores datasets, filters telemetry, views detections, and exports findings.
- **Automated testing:** validates core detection and timeline functionality.

## Architecture and Workflow

```text
Synthetic JSON Dataset       Windows Security Log
          |                           |
          |                           v
          |                 Windows Event Collector
          |                           |
          v                           v
          +------> Normalized Events <-+
                         |
                         v
                  Detection Engine
                         |
                         v
                   Event Timeline
                         |
              +----------+----------+
              |                     |
              v                     v
      Streamlit Dashboard    Incident Report Generator
              |                     |
              v                     v
        Analyst Review       Markdown Reports
```

## Repository Structure

```text
threat-hunting-attack-investigation-lab/
├── data/
│   ├── raw/
│   │   └── sample_events.json
│   └── normalized/
│       └── windows_process_events.json
├── detections/
├── evidence/
├── hunts/
│   └── hunt_queries.md
├── incidents/
├── reports/
│   ├── incident_report_synthetic.md
│   └── incident_report_windows.md
├── src/
│   ├── __init__.py
│   ├── detection_engine.py
│   ├── event_correlator.py
│   ├── incident_report.py
│   ├── log_normalizer.py
│   ├── timeline_builder.py
│   └── windows_event_collector.py
├── tests/
│   ├── test_detection_engine.py
│   └── test_timeline_builder.py
├── app.py
├── requirements.txt
└── README.md
```

## Detection Rules

| Rule ID | Detection | Severity |
|---|---|---|
| TH-001 | Repeated authentication failures within a time window | High |
| TH-002 | Successful login following repeated authentication failures | High |
| TH-003 | Suspicious PowerShell command indicators | Medium |
| TH-004 | Privilege change activity | High |

These rules identify patterns that warrant investigation. A rule match is not, by itself, proof of malicious activity.

## Data Sources

### 1. Synthetic lab telemetry

The synthetic dataset contains eight fictional security events designed to exercise the detection logic, including repeated login failures, a subsequent successful login, a PowerShell command indicator, and a privilege change.

This dataset is used to demonstrate expected detection behavior in a controlled environment.

### 2. Local Windows telemetry

The Windows dataset contains 100 locally collected process-creation events from Windows Security event logs.

The current collection has limited command-line information. As a result, some detections cannot be fully evaluated against this dataset. The current rules generated zero findings from the collected Windows events; this is not evidence that the system is free of threats.

## Technology Stack

- Python
- Streamlit
- Pandas
- Pytest
- JSON
- Windows Security Event Logging
- PowerShell
- Git and GitHub

## Installation

### Prerequisites

- Python 3.10 or later
- Git
- Windows for the Windows telemetry collection component

### Set up the project

Clone the repository and enter the project directory:

```bash
git clone https://github.com/Mosinmi/threat-hunting-attack-investigation-lab.git
cd threat-hunting-attack-investigation-lab
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use this temporary setting for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

### Launch the dashboard

```powershell
streamlit run app.py
```

Use the dashboard to switch between Synthetic Lab Data and Real Windows Telemetry, explore findings, filter events, review the investigation timeline, and export findings where available.

### Generate a synthetic investigation report

```powershell
python -m src.incident_report --source synthetic
```

Output:

```text
reports/incident_report_synthetic.md
```

### Generate a Windows telemetry report

```powershell
python -m src.incident_report --source windows
```

Output:

```text
reports/incident_report_windows.md
```

### Run the automated tests

```powershell
python -m pytest -q
```

The current verified test run completed with **12 passing tests**.

## Threat Hunting Queries

The `hunts/hunt_queries.md` file documents investigation approaches for:

1. Repeated authentication failures
2. Successful login following repeated failures
3. Suspicious PowerShell command indicators
4. Unexpected privilege changes
5. Host-centred event correlation

Each hunt includes its objective, relevant data, investigation guidance, and limitations.

## Sample Results

| Dataset | Events analyzed | Findings generated |
|---|---:|---:|
| Synthetic lab telemetry | 8 | 4 |
| Windows process telemetry | 100 | 0 |

These results reflect the current datasets and implemented rules. They are not a measurement of overall system security.

## Limitations

- Windows telemetry currently lacks command-line information for the collected events.
- Authentication detections require suitable authentication-event data.
- Detection coverage is limited to the rules implemented in the project.
- Process names and file paths alone are insufficient to confirm malicious activity.
- The synthetic dataset is illustrative, not evidence of a real cyberattack.
- No automatic containment, account modification, or other live response action is performed.
- Results should be validated against original logs and relevant surrounding evidence.

## Ethical Scope

This project is intended for defensive security education, authorized local telemetry analysis, and cybersecurity portfolio demonstration.

The lab uses synthetic events and locally collected telemetry. Findings are investigation leads and should be validated before incident conclusions or response actions are taken.

## Future Improvements

- Add authentication and network telemetry correlation.
- Improve event normalization across Windows event sources.
- Add configurable detection thresholds and time windows.
- Integrate Sigma-style detection rules.
- Add MITRE ATT&CK technique mappings.
- Expand unit tests and introduce detection regression tests.
- Add optional alert severity scoring and structured JSON reports.
- Improve process context and command-line visibility through explicitly configured, privacy-conscious audit collection.

## Author

**Mosinmi**  
Computer Engineering Graduate | Cybersecurity | SOC Analysis | Threat Hunting

GitHub: https://github.com/Mosinmi

---

*Built as a practical threat-hunting and attack-investigation lab for my cybersecurity portfolio development.*