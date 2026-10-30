# Microsoft Identity Lab Runbook

## Safety boundary

`Bluex-Windows` is a read-only template reference. Never run Sysprep, domain promotion, or topology mutation in that VM. All mutable paths must resolve below `C:\Hyper-V\BluexLab\Identity`; exact target names are `ID-DC01`, `ID-RODC01`, and `ID-SRV01`. The baseline network is the private `Bluex-Identity` switch with no NAT adapter.

## Plan-only gate

1. Run `Test-IdentityLabPreflight` and both `New-*` functions without `-Apply`.
2. Persist canonical plan JSON under `Identity\Plans` only after reviewing exact names, paths, addresses, MAC addresses, and the private-switch type.
3. Record source VM, switch, checkpoint, and VHD hashes before and after plan-only execution. They must remain unchanged.
4. Stop if any target VM exists or `Bluex-Identity` exists with a type other than `Private`.

## Template boundary

Export only the `tools-installed` checkpoint into `TemplateSource`. Import the exported copy as `ID-TEMPLATE-WORK`; run Sysprep `/generalize /oobe /shutdown` only in that copy. Keep the PowerShell Direct session alive until Sysprep exits and the temporary VM reaches `Off`; a detached process can be interrupted when its user session closes. Never retry generalization on a partially generalized image. Retain that copy for diagnosis, import a fresh source export, and start again.

Before exporting the generalized template, require all of the following:

- Sysprep exits with code zero and `Sysprep_succeeded.tag` exists.
- `ImageState` is `IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE`.
- The setup log records successful generalization and shutdown.
- Any firmware BCD diagnostic is immediately followed by successful BCD generalization with status `0x0`; every other unresolved setup error blocks the export.

Export the shut-down generalized copy into `GeneralizedTemplate`, set the parent VHD read-only, and remove only the temporary VM registration. Retain both plan JSON and source/export hashes. Failed attempts remain under `FailedAttempts` until a deliberate retention decision is made.

## Private topology

Create one differencing disk per node from the generalized read-only parent. Connect each VM only to `Bluex-Identity`, enable Secure Boot, assign the exact static MAC from the plan, and disable automatic checkpoints. Configure addresses inside guests only after unique machine SIDs are observed. Remove transient answer files from every live node after first boot; the `generalized` checkpoints must predate answer-file injection and therefore contain no reusable credential material.

## Verification gates

- All VMs are Generation 2 with Secure Boot enabled.
- Each active checkpoint/differencing chain terminates at the expected read-only generalized parent.
- Each guest has a unique machine SID, hostname, IP address, and MAC address.
- No guest has an adapter on `Bluex-NAT`, an external switch, or a default route.
- Clocks are synchronized to the isolated RWDC after forest creation.
- System and Directory Service event logs contain no unresolved critical startup events.
- No transient answer file remains on a live node.
- Create the `generalized` checkpoint before installing AD DS roles.

## Forest bootstrap and adapter ownership

Select the adapter by the exact `Microsoft Hyper-V Network Adapter` description. Do not select the first active adapter: the capture adapter can be active first and can otherwise receive the identity-lab address. Bind the static identity address and DNS server only to the Hyper-V adapter, disable DNS registration on every other adapter, and remove any stale identity address from those adapters before domain discovery.

Create the `idlab.test` forest on `ID-DC01`, then require the Windows Server 2025 forest and domain modes, schema version 91, one KDS root key, and the complete dMSA attribute set. Pre-create and promote `ID-RODC01` only after the RWDC passes those gates. Join `ID-SRV01` last and require a passing secure-channel check. The Kerberos operational log name on this build is `Microsoft-Windows-Kerberos/Operational` and its provider is `Microsoft-Windows-Security-Kerberos`.

Create checkpoints in this order:

1. `forest-preflight` before AD DS mutation.
2. `forest-ready` after RWDC forest services are healthy.
3. `rodc-ready` after RODC replication and member secure-channel checks pass.
4. `dmsa-baseline` only after the service graph is replicated and independently read from both DCs.

## dMSA baseline and lifecycle

Keep the delegated managed service account in `CN=Managed Service Accounts,DC=idlab,DC=test`; creating it in the custom lab OU causes migration command rejection on this build. Resolve `SupersededAccount` to the legacy account distinguished name, not its `sAMAccountName`.

The sealed baseline has these properties:

- Legacy service account enabled with AES128/AES256, its original SPN, one delegation target, and the non-enforced lab authentication policy.
- dMSA state `0`, AES128/AES256, no migration links or temporary ACL edges, and only `ID-SRV01` in `PrincipalsAllowedToRetrieveManagedPassword`.
- RWDC and RODC core graph documents equal after explicit domain and configuration partition replication.

Observed lifecycle transitions on build 26100 are:

| Operation | Before | After | Additional observation |
| --- | ---: | ---: | --- |
| Start | 0 | 1 | Reciprocal links and two temporary ACL edges appear; the legacy account remains enabled. |
| Complete | 1 | 2 | SPN, delegation target, and authentication policy transfer; temporary ACL edges are removed and the legacy account is disabled. |
| Undo | 1 | 0 | Links and transferred state are removed, but the machine enrollment list is cleared. |
| Reset | 2 | 0 | Links and transferred state are removed, but the machine enrollment list is cleared. |

The build-created dMSA starts at state `0`; the documented standalone state `3` was not observed and remains an inconclusive compatibility observation. Because Undo and Reset clear machine enrollment, neither operation is an exact baseline restore. Only restore all three exact `dmsa-baseline` checkpoints, start the RWDC first, wait for ADWS, and then start the RODC and member. Prove the RWDC full digest and the RWDC/RODC core graph digests before beginning another mutating case.

## RODC and event observations

A migration Start explicitly targeted at `ID-RODC01` produced a local state `1`, reciprocal links, and two temporary ACL edges on the read-only DC while the RWDC remained at state `0`. Attribute metadata named the RODC NTDS instance as the originating server. Forced RWDC-to-RODC replication did not converge the graph, and the local RODC state persisted across restart. Preserve this as a bounded protocol-state deviation for specification review; do not classify it from the command result alone.

Events 307, 308, and 309 are present in the local provider metadata. They were not emitted after direct service logon, local-system ticket refresh, or Service Control Manager attempts in states `1` and `2`. Record this result as inconclusive and retain the empty event window alongside the directory snapshots. Never infer an event from the directory transition.

Every evidence run must contain only normalized graph fields, event IDs/counts, stable reason codes, and SHA-256 artifact digests. Seal `evidence.jsonl` with `manifest.json`, validate the manifest in the Ubuntu VM, and restore the exact baseline checkpoints after the final case.
