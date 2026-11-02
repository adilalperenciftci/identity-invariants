# RODC-directed dMSA migration leaves a partial local graph after full synchronization

## Product and build

- Windows Server 2025, build 26100
- Active Directory Domain Services
- Delegated Managed Service Accounts
- Isolated forest: `idlab.test`

## Category

Reliability / documentation. No security boundary impact was identified.

## Description

Invariant `DMSA-RWDC-001` cites the Windows Server 2025 *Set up delegated
Managed Service Accounts* documentation, section *Prerequisites*: migration
graph changes require a writable domain controller, and an RODC observation
does not count as a successful write. Starting migration with the RODC selected
as the directory server nevertheless persisted a local migration graph. The
dMSA gained `msDS-DelegatedMSAState` and
`msDS-ManagedAccountPrecededByLink`; the legacy account gained
`msDS-SupersededManagedAccountLink` and
`msDS-SupersededServiceAccountState`. The writable DC remained unchanged at
state 0. A forced full inbound synchronization removed the local state value
and temporary ACL edges but retained both reciprocal links and the legacy
superseded state. A subsequent password-replication-policy change did not
reconcile that partial graph.

The condition affects the documented writable-DC and convergent-directory
boundary. I found no authorization impact: a service ticket pinned to the RODC
was issued both before and after the local write, and managed-account retrieval
remained false in both states. Group/claims construction was not directly
observable through an installed bounded interface in this lab. The suggested
vendor category is reliability/documentation rather than security.

## Preconditions

1. One writable DC, one RODC, and one member server in the same isolated
   Windows Server 2025 build 26100 forest.
2. A legacy service account and delegated managed service account at the
   documented pre-migration baseline.
3. The RODC selected explicitly for the migration operation.

## Reproduction steps

1. Restore all three hosts to the `dmsa-baseline` checkpoint and verify the
   RWDC and RODC graph digests.
2. Record the four selected migration attributes and their replication
   metadata from both DC views.
3. Direct the documented Start migration operation to `ID-RODC01`.
4. Re-read the four attributes on both DCs. Observe state 1, reciprocal links,
   and two temporary ACL edges only in the RODC view; the RWDC remains at state
   0.
5. Pin the member secure channel and a service-ticket request to the RODC, then
   record ticket issuance and managed-account retrieval decisions.
6. Force full inbound synchronization from `ID-DC01` to `ID-RODC01` and repeat
   the graph snapshot. Observe state 0 and zero temporary ACL edges, but one
   retained predecessor link and legacy superseded state 1.
7. Apply one reversible password-replication-policy allow/prepopulate change,
   synchronize, and repeat the snapshot. Observe the same partial graph.
8. Restore the checkpoint and repeat independently.

## Observed versus documented behavior

Documented expectation: the RODC is not a successful target for migration
graph changes, and synchronization should leave its directory view convergent
with the authoritative writable DC. Observed behavior: the RODC accepts and
persists four local graph changes, and full inbound synchronization produces a
third, partial state rather than the unchanged writable-DC graph.

## Impact

The RODC can retain migration links and legacy superseded state that are absent
from the writable DC. Components or operators reading the RODC view can
therefore observe a migration relationship that is neither authoritative nor
fully cleared by synchronization. No change to ticket issuance or managed
password retrieval was observed, so this report does not claim a security
boundary violation.

## Reproducibility and evidence

Both runs began from checkpoint `dmsa-baseline` and independently reproduced
the same normalized states and graph digests.

- Run A: restored `2026-11-02T01:47:15.8474612Z`; observed
  `2026-11-02T01:48:20.844634Z`; ledger case
  `dmsa-rodc-convergence-run-a`.
- Run B: restored `2026-11-02T01:52:20.6019097Z`; observed
  `2026-11-02T01:53:28.8448761Z`; ledger case
  `dmsa-rodc-convergence-run-b`.
- RODC post-Start graph digest, both runs:
  `d197bb59b47506ff973f8d583e37f06a9ef584ad32b2711da18ec3846f6c77a2`.
- RODC post-sync and post-PRP graph digest, both runs:
  `ed52d71a8afb2f3b89c132eee41064ff4f11f9b183c8bf7a53806b518ad12f5a`.
- Sealed ledger SHA-256:
  `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33`.

The normalized evidence is in `evidence/program1b/evidence.jsonl`; the seal and
record count are in `evidence/program1b/manifest.json`.
