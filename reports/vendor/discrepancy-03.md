# RODC-local dMSA migration grants a non-authoritative object right

## Product and build

- Windows Server 2025, build 26100
- Active Directory Domain Services
- Delegated Managed Service Accounts
- Isolated forest: `idlab.test`

## Category

Security / authorization consistency. Severity is not assessed.

## Description

Invariant `DMSA-RWDC-001` cites the Windows Server 2025 *Set up delegated
Managed Service Accounts* documentation, section *Prerequisites*: dMSA
migration graph changes require a writable domain controller. Program 1b
showed that directing Start migration to an RODC nevertheless creates a local
partial graph while the writable DC remains unchanged.

This follow-up evaluated the dMSA object's security descriptor with Windows
Authz in S0, S1, and S2 from both DC views. In S1, the RODC descriptor added
two allow ACEs for the legacy service-account principal. The effective-access
check granted that principal `WriteProperty` for
`msDS-GroupMSAMembership` and returned maximum-access mask `0x00020094`.
The authoritative RWDC descriptor denied the same property right and returned
`0x00000004`. The member computer principal's result remained unchanged.

The right granted was `WriteProperty` on `msDS-GroupMSAMembership` for the
legacy service-account principal, and it was granted only by the S1 RODC view.

## Preconditions

1. One writable DC, one RODC, and one member server in the same isolated
   Windows Server 2025 build 26100 forest.
2. A legacy service account and a dMSA at the documented pre-migration
   baseline.
3. The RODC selected explicitly for the Start migration operation.

## Reproduction steps

1. Restore all three hosts to the `dmsa-baseline` checkpoint.
2. Verify state 0 and the baseline graph digests from both DC views.
3. Enable Logon and Group Membership auditing on the member server.
4. Record service-logon, group-membership, managed-retrieval, normalized
   security-descriptor, and Authz effective-access results from both views.
5. Direct Start migration to `ID-RODC01` and repeat all observations.
6. In the S1 RODC view, evaluate the legacy and member computer principals
   against the dMSA object's descriptor, including the
   `msDS-GroupMSAMembership` object type.
7. Compare the same checks with the S1 `ID-DC01` descriptor.
8. Force full inbound replication from `ID-DC01` to `ID-RODC01`, repeat the
   checks for S2, restore the checkpoint, and reproduce independently.

## Expected versus observed behavior

Expected: selecting an RODC for a migration operation does not create an
authorization decision that is absent from the authoritative writable-DC
view.

Observed: S1 on the RODC granted the legacy principal an object-specific dMSA
write right that the S1 RWDC descriptor did not grant. Full inbound
replication removed the two temporary ACEs and the effective-access difference
in S2.

## Impact

The same principal receives different authorization data depending on which
DC view is evaluated. In the bounded S1 state, the RODC grants the legacy
principal permission to write the dMSA group-membership control attribute
while the authoritative RWDC does not.

No successful directory write was attempted under the legacy identity. No
change was observed in legacy service-logon success, its ten-group SID digest,
the dMSA service-logon result, managed retrieval, or the member computer's
effective rights. This report therefore claims the reproduced authorization
decision inconsistency only; it does not claim a downstream privilege change.

## Reproducibility and evidence

Both runs began from `dmsa-baseline` and independently produced identical
normalized results.

- Run A: `2026-11-02T21:51:26.1246960Z` through
  `2026-11-02T21:52:10.7114990Z`.
- Run B: `2026-11-02T21:54:02.6244540Z` through
  `2026-11-02T21:54:47.3813996Z`.
- S1 RODC effective-access digest, both runs:
  `cb2ac8c48b93e61fd3bffe46a858b811bd47c81cdf8e7f4c80380de1e33076a2`.
- All other effective-access cells:
  `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e`.
- Evidence case IDs: `program1c-security-descriptor-run-a`,
  `program1c-security-descriptor-run-b`,
  `program1c-effective-access-run-a`, and
  `program1c-effective-access-run-b`.
- Sealed ledger SHA-256:
  `0c0955044d96cb4db1b81efcdd9cec8def4b10d70d7b8d82fe85c690e1cde0ac`.

The complete digest matrix is in
[`reports/program1c-closure.md`](../program1c-closure.md). The normalized
evidence and manifest are in `evidence/program1c/`.
