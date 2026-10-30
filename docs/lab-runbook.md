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

## PAC issuance observations

Capture Kerberos traffic on the adapter that owns `172.28.30.20`. On `ID-SRV01` this is `Ethernet`, backed by the `Microsoft Hyper-V Network Adapter`. `Ethernet 3` is the Npcap loopback adapter with a link-local address and must not be selected by ordinal position. Require one exact interface-name match before starting `dumpcap`.

Use only the lab-owned `pac-client` and `pac-service` accounts and the `HTTP/pac-service.idlab.test` SPN. Generate the transient service keytab with `ktpass +rndPass`; do not place a password in a command argument, file, or evidence record. Pre-populate both account secrets on `ID-RODC01`, then prove the revealed-account state before requesting a ticket. `klist add_bind` requires an elevated local token on this build, so the member-side request harness temporarily uses an elevated scheduled task. This elevation changes only the member token; the domain principal and domain group graph remain unchanged. Exact checkpoint restore is mandatory after the run.

The bounded final service-ticket run produced these observations; account key versions are run metadata and can increase after another lab password rotation:

| Field | RWDC | RODC |
| --- | --- | --- |
| KDC source | `172.28.30.10` | `172.28.30.11` |
| Service ticket key version | `16` | `16` |
| KDC key version | `2` | `1` |
| RODC identifier | absent | `4543` |
| PAC buffer types | `1,6,7,10,12,16,19` | `1,6,7,10,12,16,19` |
| Signature roles | server, KDC, ticket, extended KDC | server, KDC, ticket, extended KDC |

The RODC TGT metadata used composite key version `297730049`, equal to `4543 << 16 | 1`. Do not derive an RODC identifier from the service-ticket key version: the service ticket remains encrypted with the service account key, while the RODC identifier belongs to KDC key and PAC signature metadata. RODC KDC, ticket, and extended-KDC signature buffers carried the additional two-byte identifier; the server signature did not.

`PAC_ATTRIBUTES_INFO` and `PAC_REQUESTOR` were absent from both decoded service tickets after same-domain domain-local membership processing. This is a direct TGS observation, not proof of the encrypted TGT payload. Preserve requestor binding at that boundary as inconclusive unless a separately authorized TGT decoding method supplies bounded evidence. Do not infer TGT buffer presence from the service ticket alone.

Pass only the exact type-128 authdata region to the bounded PAC parser. Persist frame number, exact KDC address, key versions, buffer metadata, field-specific signature digests, and capture/PAC SHA-256 values. Delete raw JSON input in a `finally` block, then delete the keytab and packet captures before restoring the VMs. The sealed Task 8 ledger contains two normalized records and has SHA-256 `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`.

Every evidence run must contain only normalized graph fields, event IDs/counts, stable reason codes, and SHA-256 artifact digests. Seal `evidence.jsonl` with `manifest.json`, validate the manifest in the Ubuntu VM, and restore the exact baseline checkpoints after the final case.

## Closed observation gates

Run the Entra and Cloud Kerberos gates only as described in
`docs/entra-observation-runbook.md`. The current isolated environment has no
disposable tenant context, Azure AD Kerberos object, or Windows 11 client. Both
Entra executions and all Cloud Kerberos client-dependent checks must therefore
remain closed with zero external requests. RWDC-local directory reachability
is environment context only; it does not satisfy the Windows 11 client
line-of-sight invariant.

After any checkpoint restore, do not infer RODC readiness from an open TCP port
or running ADWS service. Require successful `Get-ADUser` and
`Get-ADServiceAccount` queries explicitly targeting `ID-RODC01` before hashing
the replicated graph.

## Public evidence assembly

The committed `evidence/evidence.jsonl` is a normalized index, not raw
laboratory output. Each record binds one invariant outcome to a source-ledger
SHA-256 value. The manifest binds the following source artifacts:

| Source | SHA-256 |
| --- | --- |
| Task 7 Windows ledger | `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc` |
| Task 8 PAC ledger | `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe` |
| Task 9 Cloud gate | `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271` |
| Task 9 Ubuntu Entra ledger | `9a6f96a6de428e34d2c1cd136fb3ebb631a82a33d7c3152748ca0ab028956b10` |
| Task 9 Windows Entra ledger | `683102d242f601909ae64bbff71c96ff09970e41fd842de5503e2182ee9215f7` |

The assembled 25-record ledger has SHA-256
`f2a51ed468ce95690cb8276ba766f1369e08db5c12401b78b5a634c6a41d93f2`.
Its manifest has SHA-256
`8580a3ed2fa308662442060b3251312c892ddf92a91906cef117b929176ae489`.

Assemble, verify, and render only in Ubuntu. Source paths below refer to sealed,
normalized artifacts copied into ignored private storage:

```text
PYTHONPATH=src .venv/bin/python -m identity_invariants.reports.assemble --config evidence/sources.json --source task7-windows-ledger=evidence/private/review-sources/task7.jsonl --source task8-pac-ledger=evidence/private/review-sources/task8.jsonl --source task9-cloud-gate=evidence/private/review-sources/cloud.json --source task9-ubuntu-ledger=evidence/private/review-sources/ubuntu.jsonl --source task9-windows-ledger=evidence/private/review-sources/windows.jsonl --output evidence
PYTHONPATH=src .venv/bin/python -m identity_invariants.reports.render --verify-only evidence/manifest.json
PYTHONPATH=src .venv/bin/python -m identity_invariants.reports.render --render evidence/manifest.json --catalog spec/invariants.yaml --output reports/identity-invariants.md
PYTHONPATH=src .venv/bin/pytest -q tests/integration/test_end_to_end_run.py
```

The expected report hashes are:

| Report | SHA-256 |
| --- | --- |
| `reports/identity-invariants.md` | `b1a7563fad8f26f0ecfe8b542c36fca4c03489cd1dff153a038279a7a7e4a86c` |
| `reports/identity-invariants.json` | `78483af4a330ed01127a0c2f8e3a72a8659e35d642ae8312a7c128009c4ebd41` |

## Completion gate

Before considering the identity program complete:

1. Run the complete Python suite and `compileall` in Ubuntu.
2. Verify the committed manifest and regenerate the report byte-for-byte.
3. Run every PowerShell contract suite in the Windows Server lab.
4. Confirm the three identity VMs use only `Bluex-Identity`, have no default
   route, and the member secure channel is valid.
5. Restore the exact `dmsa-baseline` checkpoint identifiers and prove these
   graph digests:
   - RWDC full graph:
     `9c19162c8e7d44ad74a1990ef5775f8fdc3b8fe7a3c2fab5e08451c2eb79ae59`;
   - RODC core graph:
     `5be77ff6160d84dcfee8cba5bb935b13f0337492676124a1b02a1e0d4771bfe2`;
   - shared core graph:
     `fd1b0cdbab699e3a765295409b2711f2b1a8da0094f022ec7de2965cfe13afd5`.
6. Scan the tracked tree for credentials, tokens, raw tickets, captures, and
   private-key material. Retain only normalized records and hashes.
