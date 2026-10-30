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
