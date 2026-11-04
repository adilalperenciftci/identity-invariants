# Program 1e progress

## 25-minute checkpoint - 2026-11-04T00:37:40Z

Tested:

- Restored all three VMs to `dmsa-baseline` independently for Run A and
  Run B.
- Enabled and verified `Microsoft-Windows-Kerberos/Operational` on every
  host before each event window.
- Set `DelegatedMSAEnabled` to DWORD `1`, restarted `ID-SRV01`, and verified
  the value and log state after restart.
- Directed Start migration to `ID-DC01`, replicated the resulting graph, and
  exercised the SCM service path, Security audit records, event windows,
  retrieval checks, and RODC pin attempt.
- Restored all three VMs to `dmsa-baseline` after Run B and left them off.

Observed:

- Both writable-DC service starts returned 1069. Security event 4625 recorded
  logon type 5, status `0xc000009a`, and substatus `0x0`; no 4624 or 4627
  record was emitted.
- Each member event window contained one event 309 and zero events 307 and
  308. Both DC windows contained zero records for all three IDs.
- RWDC retrieval remained false before and after service start. RODC secure
  channel pin returned exit 1 in both runs, so its service and retrieval
  cells remain blocked.

Next:

- Finish the blocked classification report and repository indexes, then run
  manifest, link, Python, and Pester verification before creating the PR.
