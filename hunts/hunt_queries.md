# Threat Hunting Query Library

## Project 7 — Threat Hunting & Attack Investigation Lab

This document defines repeatable hunting hypotheses for investigating the synthetic security telemetry used in this lab. Each hunt describes the behaviour of interest, the data to inspect, and the recommended investigation steps.

All current sample events are synthetic. A match is an investigation lead, not confirmation of malicious activity.

---

## Hunt 1: Repeated Authentication Failures

**Objective:** Identify a possible brute-force or password-guessing pattern.

**Data source:** Authentication events.

**Filter criteria:**
- `event_type = login_failure`
- Group events by `source_ip`.
- Examine whether the configured failure threshold is reached within the correlation window.

**Investigation steps:**
1. Identify the source IP and affected accounts.
2. Review the timestamps and frequency of failed logins.
3. Check whether failures target one account or multiple accounts.
4. Look for a subsequent successful login.
5. Determine whether the source and activity are expected.

**Potential false positives:** Mistyped passwords, stale saved credentials, or an authorized application repeatedly attempting authentication.

---

## Hunt 2: Successful Login After Repeated Failures

**Objective:** Investigate a successful authentication following repeated failures.

**Data source:** Authentication events.

**Filter criteria:**
- Find `login_success` events.
- Correlate with at least the configured failure threshold of earlier `login_failure` events.
- Require the same username and source IP.
- Restrict the correlation to the configured time window.

**Investigation steps:**
1. Validate the account owner's activity.
2. Review MFA results and authentication context when available.
3. Check the host, source IP, and session activity.
4. Search for additional suspicious actions after authentication.
5. Escalate if evidence supports possible account compromise.

**Potential false positives:** Legitimate users who mistype their passwords before successfully signing in.

---

## Hunt 3: Suspicious PowerShell Command Indicators

**Objective:** Find PowerShell executions that use encoded-command indicators.

**Data source:** Process-creation events.

**Filter criteria:**
- `event_type = process_creation`
- `process = powershell.exe`
- Command line contains `-EncodedCommand` or `-enc `.

**Investigation steps:**
1. Preserve and inspect the original command line.
2. Identify the initiating user and host.
3. Review parent and child processes when available.
4. Establish whether the execution was expected and authorized.
5. Correlate with network connections, script activity, and nearby security events.

**Potential false positives:** Authorized administrative scripts and legitimate automation.

**Limitation:** An encoded-command indicator alone does not establish malicious intent.

---

## Hunt 4: Unexpected Privilege Changes

**Objective:** Identify account or group privilege changes that require review.

**Data source:** Privilege-change events.

**Filter criteria:**
- `event_type = privilege_change`

**Investigation steps:**
1. Identify the actor, target account, and changed privilege or group.
2. Verify the change against an approved request or change record.
3. Review surrounding authentication and process events.
4. Check whether the actor had an appropriate administrative role.
5. Escalate unexplained or unauthorized changes.

**Potential false positives:** Approved administration, onboarding, or access-maintenance activities.

---

## Hunt 5: Host-Centred Event Correlation

**Objective:** Build a chronological view of activity on a host associated with a detection.

**Data source:** All available normalized events.

**Filter criteria:**
- Select the host associated with a finding.
- Sort matching events by timestamp.
- Include related detection rule IDs where available.

**Investigation steps:**
1. Establish the earliest relevant event.
2. Identify authentication, process-creation, and privilege-change activity.
3. Compare event times and users.
4. Look for suspicious sequences or gaps in available telemetry.
5. Record the evidence, uncertainties, and recommended next actions.

**Potential limitation:** Missing logs, clock differences, or incomplete event fields may prevent a reliable sequence from being established.

---

## Investigation Documentation Checklist

- [ ] Record the hunt hypothesis and reason for investigation.
- [ ] Record the relevant event IDs and timestamps.
- [ ] Identify affected hosts, accounts, and source IPs.
- [ ] Separate observed evidence from assumptions.
- [ ] Document possible benign explanations.
- [ ] Record the investigation outcome and confidence level.
- [ ] Recommend containment or escalation only when justified by the evidence and applicable procedures.

## Scope and Safety

This query library is for defensive analysis of synthetic or authorized telemetry. The current project does not perform live containment or modify endpoint configurations.