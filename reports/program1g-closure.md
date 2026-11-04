# Program 1g KDS root-key repair and Program 1e re-run

## Classification

Part 1 achieved a **context-specific local repair**, but the required
two-DC visibility gate failed. Part 2 is therefore **blocked and not
started**.

The measured cause of `0x80070032` is the invocation context: the same
backdated `Add-KdsRootKey` call failed from the remote domain-administrator
session before and after `KdsSvc` was started, but succeeded from a local
SYSTEM/highest process on `ID-DC01`. The lower-level reason that the remote
API reports "request not supported" was not exposed by the available logs.

## Part 1 diagnosis

| Item | Observed | Verdict |
| --- | --- | --- |
| KDS service | Manual/Stopped, LocalSystem; process ID 0 | Repair a indicated |
| Windows features | `AD-Domain-Services` and `RSAT-AD-PowerShell` installed | Present |
| `Get-KdsConfiguration` | Returned a KDS server configuration object | Repair b not indicated |
| Initial remote add | `0x80070032`; KDS service still stopped | Reproduced |
| Repair a | Service changed to Manual/Running; identical add still returned `0x80070032` | Did not repair creation |
| Repair c | Local SYSTEM/highest scheduled task accepted the same ten-hour backdated call | Worked on RWDC |
| KDS Operational log | Enabled; five bounded records, IDs 4005, 4002, 4005, 4002, 4004; only digests retained | Diagnostic record retained |

The local creation returned KeyId digest
`906ce0aa72a5d7804c2ec93e71c19b0ac753699347fa352c569d5c1e53e887ab`
with requested effective time `2026-11-03T18:57:39.0269217Z`. A subsequent
local SYSTEM inventory on the RWDC returned one aggregate root-key record.
The cmdlet-rendered effective values were
`10/29/2026 16:54:50` and `11/03/2026 10:57:39`; the rendered creation values
were `10/30/2026 02:54:50` and `11/03/2026 20:57:40`. These values are
recorded as rendered because the cmdlet exposed both properties as arrays.
No key material was retained.

## Replication gate

The Configuration naming context was replicated directly and then with a
full bounded synchronization; both commands returned exit 0.

| View | First/last observation | Root-key count | Verdict |
| --- | --- | ---: | --- |
| RWDC local SYSTEM | `2026-11-04T04:59:02.7416249Z` / `2026-11-04T05:00:51.6427709Z` | 1 | Visible |
| RODC local SYSTEM | `2026-11-04T04:59:12.4164323Z` / `2026-11-04T05:00:58.0032544Z` | 0 | Not visible |

RWDC visibility was observed within approximately 84 seconds of the local
creation request. RODC visibility was still absent after approximately 199
seconds and two successful Configuration replication calls. Therefore no
matching KeyId digest could be recorded on `ID-RODC01`.

## Retrieval decisions

| Stage | RWDC | RODC |
| --- | --- | --- |
| Before repair | Denied in Program 1f | Denied or affinity-blocked in Programs 1c-1f |
| After local repair | Not measured: two-DC gate failed first | Not measured: key inventory remained empty |

The instructions prohibited Part 2 until the same key was visible on both
DCs. Retrieval was therefore not re-tested under the partial repair, and no
claim is made that local creation changed the earlier decision.

## Part 2 Program 1e observables

| Observable | Run A | Run B |
| --- | --- | --- |
| dMSA service sign-in | Not started: Part 1 replication gate failed | Not started |
| Events 307/308/309 | Not collected | Not collected |
| Group-membership event 4627 | Not collected | Not collected |
| Managed-password retrieval | Not collected | Not collected |

The Program 1e classification remains **blocked**. Discrepancy-02 stays on
hold; there is no new evidence about events 307, 308, or 309.

## Cleanup and evidence

Because Part 1 did not satisfy the gate, no `dmsa-baseline-kds` checkpoint
was created. All three VMs were restored to `dmsa-baseline` and left powered
off.

The sealed seven-record ledger SHA-256 is
`a9d49ea1f63e17f1d0492f35b590077fb473310385f84378428379055e3bac30`.

## Conclusion

The remote `0x80070032` result is context-dependent: local SYSTEM execution
on the RWDC accepted the same documented operation. That partial repair did
not meet the program's two-DC gate because the RODC continued to report no
root key after forced replication. Program 1e cannot be re-run under the
specified procedure until the RODC visibility requirement is either met or
revised against documented RODC KDS behavior.
