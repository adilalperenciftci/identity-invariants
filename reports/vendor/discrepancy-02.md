# dMSA client event behavior requires a successful sign-in re-validation

## Product and build

- Windows Server 2025, build 26100
- Active Directory Domain Services / Kerberos Operational telemetry
- Delegated Managed Service Accounts
- Isolated forest: `idlab.test`

## Status

On hold. Not ready for submission.

Program 1e corrected the two known Program 1b procedure gaps. In two
independent runs, `Microsoft-Windows-Kerberos/Operational` was enabled and
read back on all three hosts before collection. `DelegatedMSAEnabled` was set
to DWORD `1` on `ID-SRV01`, persisted across a restart, and was read back
before Start migration and service creation.

The service did not complete a dMSA sign-in in either run. SCM returned 1069,
and Security event 4625 recorded logon type 5, status `0xc000009a`, and
substatus `0x0`. No Security event 4624 or 4627 was emitted. Under the Program
1e decision rule this blocks the event-presence question: zero 307 or 308
records cannot support an absence claim without a successful documented
sign-in.

Each failed client window contained one event 309 on `ID-SRV01`. Neither DC
contained events 307-309 in either window. This is retained as an observation,
not a discrepancy, because the sign-in did not complete.

## Category

Potential telemetry / auditing behavior. No authorization or confidentiality
boundary impact was identified. No vendor report should be submitted from the
current evidence.

## Re-validation procedure

1. Restore `ID-DC01`, `ID-RODC01`, and `ID-SRV01` to `dmsa-baseline`.
2. Enable the Kerberos Operational log on every host and record its enabled
   state and current record count.
3. Set `DelegatedMSAEnabled` to DWORD `1` on the member, restart it, and read
   back both the policy and log state.
4. Direct Start migration to `ID-DC01`, confirm state 1, one predecessor link,
   and one enrolled principal in both DC views.
5. Create and start a temporary Windows service under the dMSA through SCM.
6. Record the SCM result, Security 4624/4625/4627 records, and events
   307-309 from all three bounded Operational-log windows.
7. Restore the checkpoint and repeat independently.

## Results

| Run | Service result | Security result | `ID-DC01` 307/308/309 | `ID-RODC01` 307/308/309 | `ID-SRV01` 307/308/309 |
| --- | --- | --- | --- | --- | --- |
| A | SCM 1069 | 4625, type 5, `0xc000009a` / `0x0` | `0/0/0` | `0/0/0` | `0/0/1` |
| B | SCM 1069 | 4625, type 5, `0xc000009a` / `0x0` | `0/0/0` | `0/0/0` | `0/0/1` |

The RODC secure-channel pin also returned exit 1 in both runs. RODC-pinned
service and retrieval results remain blocked and are not attributed to the
RODC.

## Evidence

- Closure report: [`reports/program1e-closure.md`](../program1e-closure.md)
- Run A cases: `program1e-client-prerequisites-run-a`,
  `program1e-service-sign-in-run-a`, and
  `program1e-kerberos-events-run-a`
- Run B cases: `program1e-client-prerequisites-run-b`,
  `program1e-service-sign-in-run-b`, and
  `program1e-kerberos-events-run-b`
- Sealed Program 1e ledger SHA-256:
  `610aaac1fd6f1d9d36e45ebf02534c79cdb08b7b0d7726c98f5c7dc77541a8df`

The earlier Program 1b event cases remain part of the historical record, but
their absence claim is superseded by this blocked re-validation result.
