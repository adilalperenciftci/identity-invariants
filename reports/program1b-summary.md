# Program 1b Conformance Follow-up Summary

Date: 2026-11-02

Environment: isolated `idlab.test` forest; Windows Server 2025 build 26100

Baseline: `dmsa-baseline` on `ID-DC01`, `ID-RODC01`, and `ID-SRV01`

Evidence: 42 normalized records in `evidence/program1b/evidence.jsonl`; manifest SHA-256 `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33`

## Outcome

Two documented-vs-observed discrepancies met the required standard of two
independent reproductions from the named checkpoint. Neither demonstrated an
authorization or confidentiality boundary change. No third discrepancy met the
bar.

1. **RODC-directed dMSA migration leaves a partially converged local graph
   (reliability/documentation).** Invariant `DMSA-RWDC-001`, sourced from
   `DMSA-SETUP` / *Prerequisites*, requires migration graph changes to use a
   writable domain controller. From the exact baseline, directing Start to the
   RODC changed `msDS-DelegatedMSAState` and
   `msDS-ManagedAccountPrecededByLink` on the dMSA and
   `msDS-SupersededManagedAccountLink` and
   `msDS-SupersededServiceAccountState` on the legacy account, while the RWDC
   remained at state 0. Full inbound synchronization reset the local state and
   temporary ACL edges but left the reciprocal migration links and legacy
   superseded state. A subsequent password-replication-policy change did not
   reconcile the graph. The same normalized states and graph digests occurred
   at `2026-11-02T01:48:20.844634Z` and
   `2026-11-02T01:53:28.8448761Z`. RODC-issued service-ticket behavior and the
   managed-account retrieval decision were unchanged before and after the
   local write, so no security boundary impact was identified. See
   `reports/vendor/discrepancy-01.md`.

2. **Documented migration and permission-enrollment events were absent
   (telemetry).** Invariant `DMSA-EVENT-001`, sourced from `DMSA-OVERVIEW` /
   *Auditing dMSA activity*, correlates events 307, 308, and 309 with migration,
   permission enrollment, and key fetch. Provider metadata on all three build
   26100 hosts defines 307-309. Successful migration and permission-enrollment
   sequences produced zero 307/308 records in the documented Kerberos
   Operational log in independent windows at `2026-11-02T01:59:00Z` and
   `2026-11-02T02:03:00Z`. This affects audit observability, not an identity
   authorization decision. Event 309 is not included in the discrepancy: the
   lab did not complete a key-fetch operation. See
   `reports/vendor/discrepancy-02.md`.

## Ruled out, bounded, or blocked

- `DMSA-ROLLBACK-001`: Undo and Reset cleared the retrieval enrollment in both
  runs. Adding a different principal to the formerly authorized group did not
  repopulate the attribute. Only explicit re-enrollment restored one principal,
  and it restored the baseline graph digest. No authorization widening was
  observed. The host-cache ordering remains blocked because build 26100 did not
  accept the delegated account for installation before Reset; the evidenced
  consequence is reliability-only.
- Sixteen WIF, RFC 7523, RFC 8693, and OIDC invariants were exercised twice as
  local specification oracles: 49/49 tests passed with seeds 101 and 202. These
  records deliberately make no Windows or Entra product-behavior claim. Live
  product observation requires a configured disposable Entra tenant plus an
  application/federation context; a Windows 11 client is not required for these
  sixteen checks.
- `PAC-BOUNDS-001` and `PAC-ORDER-001`: the extended bounded parser suite passed
  5/5 tests twice with seeds 303 and 404, 2,600 configured property examples per
  run, inputs up to 2,048 bytes, and structured depth up to 16. No parser
  disagreement or product deviation was observed.

## Invariants touched and next prerequisites

The follow-up touched `DMSA-RWDC-001`, `DMSA-ROLLBACK-001`,
`DMSA-EVENT-001`, `WIF-TRANSPORT-001`, `WIF-TYPE-001`, `WIF-MATCH-001`,
`WIF-TIME-001`, `WIF-REPLAY-001`, `WIF-FLEX-001`, `WIF-KEY-001`,
`STS-REQ-001`, `STS-ACTOR-001`, `STS-TARGET-001`, `STS-RIGHTS-001`,
`STS-LIFETIME-001`, `OIDC-ISS-001`, `OIDC-AUD-001`, `OIDC-NONCE-001`,
`OIDC-TIME-001`, `PAC-BOUNDS-001`, and `PAC-ORDER-001`.

Program 2 can begin after restoring the three identity VMs to their baseline
checkpoints. Further identity-product work requires either the disposable Entra
tenant/application context above or a supported dMSA workload path that
successfully completes key fetch and establishes host cache state.
