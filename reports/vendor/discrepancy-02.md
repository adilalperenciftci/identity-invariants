# Documented dMSA migration and permission events are absent on build 26100

## Product and build

- Windows Server 2025, build 26100
- Active Directory Domain Services / Kerberos Operational telemetry
- Delegated Managed Service Accounts
- Isolated forest: `idlab.test`

## Status

On hold. Not to be submitted in this form. Two gaps in the Program 1b
procedure undermine the absence claim:

1. The documentation states that `Microsoft-Windows-Kerberos/Operational` is
   disabled by default. The Program 1b records show the event query and the
   provider definitions but do not record that the log was enabled on
   `ID-DC01`, `ID-RODC01`, and `ID-SRV01` before the windows opened.
2. Events 307-309 are written by the Kerberos client of the machine that
   signs in with the dMSA. The member server never completed a dMSA sign-in
   in Programs 1b-1d (status 1326/1069, event 4625), and the documented
   `DelegatedMSAEnabled` client policy was never configured in the lab. The
   directory-side cmdlets that the program used as triggers are not the
   documented event sources.

Re-validation requires: the Operational log enabled and verified on every
host, the client policy configured, a service running as the dMSA started
through the service control manager, and the event windows opened around
that sign-in. Until then the observation stands only as a lab limitation.

## Category

Telemetry / auditing. No authorization boundary impact was identified.

## Description

Invariant `DMSA-EVENT-001` cites the Windows Server 2025 *Delegated Managed
Service Accounts overview*, section *Auditing dMSA activity*, which correlates
events 307, 308, and 309 with migration, permission enrollment, and key fetch.
The local `Microsoft-Windows-Security-Kerberos` provider metadata on all three
build 26100 hosts defines events 307-309 in
`Microsoft-Windows-Kerberos/Operational`. In two independent sequences, a
successful migration transition and successful permission enrollment produced
zero event 307 and zero event 308 records on every host in the bounded event
window.

This is an audit-observability discrepancy: documented administrative state
changes are not represented in the stated operational telemetry. It does not
change an identity authorization decision. Event 309 is intentionally excluded
from this report because the lab did not successfully complete the documented
key-fetch operation; absence without that trigger would not meet the evidence
standard.

## Preconditions

1. Windows Server 2025 build 26100 AD DS forest with Kerberos Operational
   logging available.
2. A legacy service account and delegated managed service account at the
   documented pre-migration baseline.
3. Provider definitions for event IDs 307, 308, and 309 present locally.

## Reproduction steps

1. Restore `ID-DC01`, `ID-RODC01`, and `ID-SRV01` to the
   `dmsa-baseline` checkpoint.
2. Query local provider metadata and confirm that event IDs 307-309 are
   defined for `Microsoft-Windows-Security-Kerberos`.
3. Record the start time and record ID of the Kerberos Operational log on all
   three hosts.
4. Run the documented dMSA migration transition and verify its resulting
   directory state.
5. Grant the documented managed-password retrieval permission to the member
   computer and verify that the enrollment attribute contains one principal.
6. Query event IDs 307 and 308 from the bounded start/end window on all three
   hosts. Observe zero records.
7. Restore the checkpoint and repeat the complete sequence independently.

## Observed versus documented behavior

Documented expectation: migration and permission enrollment correlate with
events 307 and 308 in the Kerberos Operational log. Observed behavior: both
documented triggers completed, the provider defines both event IDs, and neither
event appeared on the writable DC, RODC, or member server in either run.

## Impact

Administrators and detection logic relying on the documented events cannot
observe these dMSA lifecycle transitions on the tested build. The affected
boundary is telemetry completeness; no authentication, authorization, or
credential-handling change was observed.

## Reproducibility and evidence

- Run A: restored `2026-11-02T01:57:38.3535086Z`; event window observation
  `2026-11-02T01:59:00Z`; ledger case
  `dmsa-documented-events-run-a`; normalized event-window digest
  `bf83f5bf9c17d7673c1b3c0b271e1994fbf55dd3130705389d1afe4501ee15c0`.
- Run B: restored `2026-11-02T02:01:54.4936024Z`; event window observation
  `2026-11-02T02:03:00Z`; ledger case
  `dmsa-documented-events-run-b`; normalized event-window digest
  `3c5a1312ba446d8ce50049c51edcd1739b1052a7d60a30f69a88a6859e926b67`.
- Sealed ledger SHA-256:
  `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33`.

The normalized evidence is in `evidence/program1b/evidence.jsonl`; the seal and
record count are in `evidence/program1b/manifest.json`.
