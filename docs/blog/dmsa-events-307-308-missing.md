---
title: "When documented dMSA events 307 and 308 are absent"
date: 2026-11-02
tags:
  - active-directory
  - detection-engineering
  - dmsa
  - windows-server
---

# When documented dMSA events 307 and 308 are absent

Delegated Managed Service Accounts (dMSAs) add lifecycle operations that
defenders may want to observe: migration from an existing service account,
enrollment of principals allowed to retrieve the managed password, and managed
key retrieval. The Windows Server 2025 documentation associates Kerberos
Operational event IDs 307, 308, and 309 with those activities. That mapping is
useful because a stable event ID gives detection engineers a direct collection
target and gives administrators a concrete way to confirm that a documented
operation entered the audit stream.

Program 1b of the `identity-invariants` project checked that mapping in a
bounded Windows Server 2025 lab. On build 26100, successful migration and
permission-enrollment operations produced no 307 or 308 records in the tested
event windows, even though the local provider metadata defined both event IDs.
This article describes the observation, its limits, and the evidence sources
that can supplement event-based monitoring. It does not claim an authorization
or confidentiality boundary change.

## Why documented events matter for detection

An event-to-operation mapping is a contract used by several operational
layers. A collection policy decides which channels and IDs to forward. A
detection rule decides which fields and sequences to evaluate. An
investigation procedure uses the resulting records to reconstruct a lifecycle
change. If the expected record is absent, all three layers can appear healthy
while providing no evidence for the operation being checked.

That does not make a missing event a security-boundary failure. It is a
telemetry question: did the documented administrative transition produce the
record that defenders were told to expect? Keeping that distinction matters.
The Program 1b work classified this result as a telemetry discrepancy and did
not infer a change in authentication, authorization, managed-password access,
or confidentiality.

## Lab and method

The observation came from the isolated `idlab.test` forest. The three hosts
were `ID-DC01`, `ID-RODC01`, and `ID-SRV01`, all running Windows Server 2025
build 26100 on a private virtual switch without a default route. Each
independent run began by restoring the same `dmsa-baseline` checkpoint. The
checkpoint name and VM checkpoint identifiers were retained in the normalized
ledger so that the two runs were tied to the same starting state.

Before evaluating the trigger windows, the local
`Microsoft-Windows-Security-Kerberos` provider metadata was queried on all
three hosts. It defined event IDs 307, 308, and 309 for
`Microsoft-Windows-Kerberos/Operational`. Each run then completed two bounded
operations: a dMSA migration transition and permission enrollment. The event
channel was queried only for the recorded start and end window, and the public
evidence retained event IDs, counts, provider and log names, timestamps, build
data, and state values rather than event messages or reusable identity
material.

The complete sequence ran twice after separate checkpoint restores. Run A's
event observation was recorded at `2026-11-02T01:59:00Z`; Run B's was recorded
at `2026-11-02T02:03:00Z`. The results were written as separate ledger cases,
then the 42-record Program 1b ledger was sealed by its manifest. One
reproduction would have remained an anomaly; the second matching reproduction
met the project's discrepancy threshold.

## What was observed

Both runs reported the same bounded result:

- the migration trigger completed, with zero event 307 records;
- permission enrollment completed, with zero event 308 records;
- the provider definitions for 307, 308, and 309 were present; and
- the queried count was zero on `ID-DC01`, `ID-RODC01`, and `ID-SRV01`.

The observation is narrower than saying that these events never occur. It
applies to the documented triggers, topology, logging channel, checkpoint, and
build that were actually tested. The evidence does not establish why the
events were absent, and the write-up does not propose a product root cause.

The same program also checked service decisions around the RODC-local dMSA
state follow-up. Ticket issuance was unchanged before and after that local
state transition, and managed-account retrieval remained false. Those results
support the narrow classification used here: telemetry was missing, but no
authorization or confidentiality boundary change was observed.

## Detection coverage when the events are absent

Until event behavior is validated for a deployment's exact build and logging
configuration, event IDs 307 and 308 should not be the only evidence source
for these transitions. A practical validation starts by confirming that the
Kerberos Operational channel is collected and that the provider defines the
expected IDs. A controlled administrative transition can then establish
whether the event appears in that environment before a detection rule treats
its absence as meaningful.

Directory state provides a separate observation surface. The Program 1b
records identified changes to `msDS-DelegatedMSAState` and
`msDS-ManagedAccountPrecededByLink` on the dMSA side, and to
`msDS-SupersededManagedAccountLink` and
`msDS-SupersededServiceAccountState` on the legacy-account side. Permission
enrollment was tracked as the count of enrolled principals. Monitoring those
values can show that a lifecycle transition changed directory state even when
the expected operational event is absent.

Replication context is also important. In the RODC follow-up, the writable-DC
view remained unchanged during the RODC-local Start operation. A forced full
inbound synchronization cleared the local state and temporary ACL edges but
left a predecessor link and the legacy superseded state in the RODC view.
Collection that records the DC queried, attribute state, and replication
metadata can therefore distinguish an authoritative writable-DC transition
from a local or partially reconciled view.

These directory observations are compensating evidence, not a claim that they
are equivalent to the documented events. They require their own collection,
retention, and baseline decisions. Their value is that they expose state the
lab actually observed and give defenders a second way to validate whether a
dMSA lifecycle transition occurred.

## Limitations

This result covers one isolated forest and Windows Server 2025 build 26100. It
does not establish behavior on later servicing levels, different topologies,
or different channel configurations. The test retained bounded normalized
metadata rather than raw event payloads, tickets, or credentials.

Event 309 is excluded. Managed-key retrieval did not complete in the lab, so
the documented key-fetch trigger was not satisfied. A zero count without that
trigger is not evidence of a discrepancy. The work also makes no claim about
hosted identity services or an Entra tenant.

Most importantly, the result is about telemetry completeness. No
authorization or confidentiality boundary change was observed, and no
security impact is claimed.

## Reproduction and evidence

The repository contains the
[self-contained telemetry report](../../reports/vendor/discrepancy-02.md), the
[normalized Program 1b ledger](../../evidence/program1b/evidence.jsonl), and
its [sealed manifest](../../evidence/program1b/manifest.json). The relevant
case IDs are `dmsa-documented-events-run-a` and
`dmsa-documented-events-run-b`. The report records the exact preconditions,
bounded reproduction steps, timestamps, and stated impact without requiring
raw laboratory material.
