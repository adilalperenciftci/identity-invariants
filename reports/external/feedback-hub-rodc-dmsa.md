# Windows Server Feedback Hub entry

## Title

RODC-directed dMSA migration leaves a partial local graph after synchronization

## Category

Active Directory / Domain Services

## Build

Windows Server 2025 build 26100

## Summary

A dMSA migration operation directed to `ID-RODC01` persisted migration state
and reciprocal links in the RODC view while `ID-DC01` remained at state 0.
Forced inbound synchronization cleared the RODC-local state value and
temporary ACL edges, but the predecessor link and legacy superseded state
remained. A subsequent password-replication-policy change and synchronization
did not reconcile that partial graph. The result reproduced in two independent
runs from the same checkpoint.

## Reproduction steps

1. In an isolated Windows Server 2025 forest with one writable DC, one RODC,
   and one member server, restore all hosts to the lab's pre-migration
   `dmsa-baseline` checkpoint.
2. Read the dMSA migration state and reciprocal-link attributes from both DC
   views.
3. Direct the documented Start migration operation to `ID-RODC01`.
4. Read the attributes again. The RODC view reaches state 1, contains reciprocal
   links, and has two temporary ACL edges; the writable DC remains at state 0.
5. Force full inbound synchronization from `ID-DC01` to `ID-RODC01` and repeat
   the graph snapshot.
6. Observe state 0 and zero temporary ACL edges on the RODC, while one
   predecessor link and legacy superseded state 1 remain.
7. Apply one reversible password-replication-policy change, synchronize, and
   confirm that the partial graph remains.
8. Restore the checkpoint and repeat the sequence independently.

## Expected versus observed

Expected: migration graph changes require a writable domain controller, and
the RODC view does not retain a migration relationship absent from the
writable DC.

Observed: the RODC accepted four local migration-graph changes. Full inbound
synchronization produced a partial state rather than the unchanged writable-DC
graph in both runs.

## Impact

Operators or components reading the RODC can observe migration links and a
legacy superseded state that are absent from the writable DC. Ticket issuance
and managed-account retrieval decisions did not change in the bounded checks.
No security boundary impact identified. No authorization or confidentiality
boundary change was observed. Category: reliability/documentation.

Full evidence and timestamps:
[RODC dMSA discrepancy report](../vendor/discrepancy-01.md).

## Addendum: non-authoritative object right (Program 1c/1d)

In the same S1 state, the RODC's local security descriptor of the dMSA
object carries an allow ACE granting the legacy service-account principal
`WriteProperty` on `msDS-GroupMSAMembership`; the writable DC's descriptor
does not, and the Windows Authz effective-access evaluation reports the right
only in the RODC view. A modify request for that attribute under the legacy
identity returns an LDAP referral from the RODC and is denied (result 50) by
the writable DC, so the right is not enforceable. It is an inconsistency in
the RODC's local copy, cleared by the next full inbound replication.
Evidence: [discrepancy-03](../vendor/discrepancy-03.md).
