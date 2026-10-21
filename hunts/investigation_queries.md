# Investigation Queries and Workflow

## Purpose

This guide provides repeatable investigation steps for the Threat Hunting
and Attack Investigation Lab. Use the synthetic dataset for demonstrations.
Investigate real endpoint telemetry only when authorized.

## 1. Repeated Authentication Failures

**Objective:** Identify repeated failed logins that may indicate password
guessing or account misuse.

**Filter:** `event_type = login_failure`

**Investigate:**
1. Group events by source IP and username.
2. Review the timestamps and frequency of failures.
3. Check whether other accounts were targeted from the same source.
4. Look for a successful login following the failures.
5. Validate whether the activity matches expected user behaviour.

**Potential false positives:** Mistyped passwords, expired credentials,
automated services, and approved authentication tests.

## 2. Successful Login After Failed Attempts

**Objective:** Identify a successful authentication after repeated failures.

**Filter:** `event_type = login_success`

**Investigate:**
1. Search for earlier failures involving the same account and source IP.
2. Establish the time gap between the failures and success.
3. Review the host, account, and subsequent activity.
4. Verify the login with the account owner or identity team when appropriate.

**Potential false positives:** Legitimate users who eventually enter the correct
password or retry after a temporary authentication problem.

## 3. Suspicious PowerShell Activity

**Objective:** Identify command-line indicators that merit review.

**Filter:** Process or command line contains PowerShell and unusual arguments,
such as encoded-command indicators.

**Investigate:**
1. Review the complete command line when available.
2. Identify the initiating process and user.
3. Correlate the event with nearby authentication and process events.
4. Check whether the activity is associated with an approved script or task.
5. Preserve relevant evidence and escalate unresolved suspicious activity.

**Limitation:** An encoded command is an indicator for investigation, not proof
of malicious activity. Missing command-line telemetry limits this hunt.

## 4. Privilege Changes

**Objective:** Review unexpected privilege or permission changes.

**Filter:** `event_type` indicates a privilege change.

**Investigate:**
1. Identify the affected account and host.
2. Establish the timestamp and initiating user or process, if recorded.
3. Verify whether a change request or administrative task exists.
4. Review nearby logon and process events.
5. Escalate changes that cannot be validated.

**Potential false positives:** Approved administration, software installation,
and routine identity-management operations.

## 5. Host-Centred Event Correlation

**Objective:** Build a chronological view of related activity on one host.

**Investigate:**
1. Select the host associated with the alert.
2. Order its events by timestamp.
3. Review authentication, process, and privilege-related activity.
4. Identify related accounts and source addresses.
5. Record the evidence supporting each conclusion.

## Evidence and Reporting Checklist

- [ ] Record the alert or detection rule ID.
- [ ] Record timestamps, host, account, and source address where available.
- [ ] Preserve relevant event IDs and original log records.
- [ ] Distinguish observed facts from hypotheses.
- [ ] Document false-positive checks and telemetry limitations.
- [ ] Record containment or escalation actions, if authorized.
- [ ] Include findings, impact assessment, and recommended remediation.

## Safety and Scope

Use synthetic events for demonstrations and only investigate systems for which
you have permission. Do not treat an isolated indicator or a lack of alerts as
conclusive proof of compromise or security.
