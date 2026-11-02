# Program 1c progress

## 20-minute checkpoint - 2026-11-02T21:53:49Z

Tested:

- Restored all three VMs to the verified `dmsa-baseline` checkpoints.
- Reproduced S0, S1, and S2 in order. The explicit full inbound replication
  from `ID-DC01` to `ID-RODC01` reproduced the Program 1b S2 digest.
- Enabled Logon and Group Membership auditing on `ID-SRV01`.
- Collected service-logon, group-membership, managed-retrieval, graph, ACL,
  and normalized security-descriptor observations from both DC views.

Observed:

- The legacy service logon succeeded in every state and view, with the same
  ten-group digest. The dMSA service logon failed consistently and generated
  a Security failure record in every state and view.
- Managed retrieval remained false in every state and view.
- S1 changed only the RODC graph and dMSA descriptor; S2 removed the two
  temporary ACL edges while retaining the previously documented links.
- The built-in Authz check found that the S1 RODC descriptor granted the
  legacy principal the `msDS-GroupMSAMembership` write right; the S1 RWDC
  descriptor did not. The member computer result did not change.

Next:

- Complete independent Run B from the restored checkpoint and compare every
  normalized digest before classifying the single-run authorization anomaly.

## Completion - 2026-11-02T22:01:00Z

Tested:

- Completed Run B from a fresh checkpoint restore.
- Compared all graph, descriptor, group, retrieval, and Authz digests between
  runs; the comparison contained zero mismatches.
- Restored all three VMs to `dmsa-baseline` and verified state 0, zero
  temporary ACL edges, no default routes, and a valid member secure channel.
- Verified the 10-record ledger manifest, relative links, 150 passing Python
  tests with 3 skips, and 53 passing Pester tests.

Observed:

- Run B reproduced the S1 RODC-only legacy-principal write right exactly.
- The result meets the Program 1c boundary-discrepancy decision rule.

Next:

- Submit `reports/vendor/discrepancy-03.md` through the vendor channel after
  review. No further laboratory work is required for Program 1c.
