# Program 1c authorization-data consistency

## Question and classification

Program 1c asked whether the RODC-local partial dMSA graph changes any
authorization data or access decision presented through `ID-RODC01` compared
with the authoritative `ID-DC01` state. The answer is **yes**. The result is a
**boundary discrepancy** under the program decision rule.

In both independent runs, the S1 RODC security descriptor granted the legacy
service-account principal `WriteProperty` for `msDS-GroupMSAMembership` on the
dMSA object. Windows Authz returned the property right as allowed and a
maximum-access mask of `0x00020094`. The same principal evaluated against the
S1 RWDC descriptor did not receive that property right and returned
`0x00000004`. The member computer result did not change. Full inbound
synchronization removed the temporary ACEs and the access difference in S2.

No service-logon, group-membership, or managed-retrieval decision changed
between views or states. The bounded check did not attempt a directory write
under the legacy identity and does not claim a downstream privilege change.

## States

- **S0:** checkpoint baseline; both DC views at migration state 0.
- **S1:** Start directed to `ID-RODC01`; RODC state 1 and RWDC state 0.
- **S2:** explicit full inbound replication from `ID-DC01` to `ID-RODC01`;
  RODC state 0, predecessor link retained, legacy superseded state retained.

Run A covered `2026-11-02T21:51:26.1246960Z` through
`2026-11-02T21:52:10.7114990Z`. Run B covered
`2026-11-02T21:54:02.6244540Z` through
`2026-11-02T21:54:47.3813996Z`. Each run started from the independently
restored `dmsa-baseline` checkpoint. Logon and Group Membership audit
subcategories were enabled on `ID-SRV01` before collection.

These quoted windows are ledger record-collection windows, not full run
durations; checkpoint restore, state transitions, and replication occurred
before the observations were normalized and sealed.

## Observable results

1. **Service authentication:** the legacy service logon succeeded in all 12
   state/view/run cells. The dMSA service logon failed with the same status in
   all 12 cells. Security log records confirmed both outcomes.
2. **Groups and claims:** the legacy identity produced ten normalized group
   SIDs with digest
   `731eec2eb17988a06849e35ef84f57c91bfc06baf597f145c38272667631de7c`
   in every cell. The dMSA group list is blocked because no dMSA service logon
   succeeded and therefore no 4627 group-membership record was emitted.
3. **Managed retrieval:** retrieval remained false in every cell.
4. **Security descriptors:** only the S1 RODC dMSA descriptor differed. It
   contained two temporary allow ACEs for the legacy principal: `GenericRead`
   and `WriteProperty` for `msDS-GroupMSAMembership`. Both disappeared in S2.
5. **Effective access:** only the S1 RODC legacy-principal result differed.
   Authz allowed the property write there and denied it in the S1 RWDC view.
   Member-computer results were identical throughout.

## Digest matrix

Each cell below is the SHA-256 digest of the normalized observable value. No
account names, group SIDs, credentials, or protocol material are included.

| Observable | State | View | Run A digest | Run B digest |
|---|---|---|---|---|
| `authentication` | S0 | RWDC | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` |
| `authentication` | S0 | RODC | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` |
| `authentication` | S1 | RWDC | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` |
| `authentication` | S1 | RODC | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` |
| `authentication` | S2 | RWDC | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` |
| `authentication` | S2 | RODC | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` | `6df9b63ccaf54669c7de2f2c552cf6779d150c6c7a0b7a6e551b33995c5a3686` |
| `group_claims` | S0 | RWDC | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` |
| `group_claims` | S0 | RODC | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` |
| `group_claims` | S1 | RWDC | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` |
| `group_claims` | S1 | RODC | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` |
| `group_claims` | S2 | RWDC | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` |
| `group_claims` | S2 | RODC | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` | `78111623846f449b323228c861285cec1b6d9aa17aa9c87dfe169111c72d8253` |
| `managed_retrieval` | S0 | RWDC | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` |
| `managed_retrieval` | S0 | RODC | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` |
| `managed_retrieval` | S1 | RWDC | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` |
| `managed_retrieval` | S1 | RODC | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` |
| `managed_retrieval` | S2 | RWDC | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` |
| `managed_retrieval` | S2 | RODC | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` | `ae40fa4fcb4ac9df63a8347d646b50f24ee5084ce8b7eaad7f8138863b337bc3` |
| `security_descriptor` | S0 | RWDC | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` |
| `security_descriptor` | S0 | RODC | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` |
| `security_descriptor` | S1 | RWDC | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` |
| `security_descriptor` | S1 | RODC | `116a345a16a0dfe8084dc0da8c2a29a6a3c7b10ee71d5ca14c1a4349b748ef8d` | `116a345a16a0dfe8084dc0da8c2a29a6a3c7b10ee71d5ca14c1a4349b748ef8d` |
| `security_descriptor` | S2 | RWDC | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` |
| `security_descriptor` | S2 | RODC | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` | `800cc911a7445b9b22aa619f1c326564c33aa12ed101371bf92a5a27bf8473a8` |
| `effective_access` | S0 | RWDC | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` |
| `effective_access` | S0 | RODC | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` |
| `effective_access` | S1 | RWDC | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` |
| `effective_access` | S1 | RODC | `cb2ac8c48b93e61fd3bffe46a858b811bd47c81cdf8e7f4c80380de1e33076a2` | `cb2ac8c48b93e61fd3bffe46a858b811bd47c81cdf8e7f4c80380de1e33076a2` |
| `effective_access` | S2 | RWDC | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` |
| `effective_access` | S2 | RODC | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` | `427bbdfc4a1dfdba488c64a8b767b14a3ef8394e8e45d52315ba46a567912d6e` |

## Conclusion

The RODC-local partial graph changes authorization data and the corresponding
effective-access decision in S1. It grants the legacy service-account
principal the `msDS-GroupMSAMembership` write right on the dMSA object even
though the authoritative RWDC view does not grant that right. The result was
identical in two independent checkpoint reproductions. The RODC line is
therefore not closed as consistent; it is carried forward as
[`discrepancy-03`](vendor/discrepancy-03.md). No other measured authorization
or authentication result changed, and the dMSA group-membership observable
remains blocked by the unsuccessful dMSA service logon.

The sealed ledger contains 10 records with SHA-256
`0c0955044d96cb4db1b81efcdd9cec8def4b10d70d7b8d82fe85c690e1cde0ac`.
