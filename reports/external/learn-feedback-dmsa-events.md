# Microsoft Learn feedback: dMSA auditing events

## Page and section

[Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview),
section **Auditing dMSA activity**.

## What the documentation states

The section associates event 307 with migration, event 308 with permission
enrollment, and event 309 with managed-key retrieval.

## What was observed

On Windows Server 2025 build 26100, the local
`Microsoft-Windows-Security-Kerberos` provider defined events 307, 308, and
309 in `Microsoft-Windows-Kerberos/Operational`. Two independent runs began
from the same `dmsa-baseline` checkpoint. Each run completed the migration and
permission-enrollment triggers, but the bounded event windows contained zero
307 records and zero 308 records on `ID-DC01`, `ID-RODC01`, and `ID-SRV01`.

Event 309 was not assessed because managed-key retrieval did not complete. No
authorization or confidentiality boundary change was observed.

## Why this matters to defenders

Detection and audit procedures based on the documented event IDs can miss the
tested dMSA lifecycle changes on this build. Administrators need to know the
validated build scope and any additional prerequisites before treating these
events as complete coverage.

## Suggested documentation change

Please document the builds and logging prerequisites on which 307-309 were
validated. If build 26100 is expected to emit 307 and 308 for these triggers,
add a verification step and a note that directory attribute and replication
metadata monitoring may be needed when the events are absent.

Evidence: [telemetry discrepancy report](../vendor/discrepancy-02.md) and
[sealed ledger manifest](../../evidence/program1b/manifest.json), ledger
SHA-256
`c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33`.
