# Program 1g progress

## Early-stop checkpoint - 2026-11-04T05:01:10Z

Tested:

- Restored all three VMs to `dmsa-baseline` and collected the ordered Part 1
  service, feature, KDS configuration, and root-key creation checks.
- Reproduced `0x80070032` before and after starting `KdsSvc`.
- Ran the same backdated creation from a local SYSTEM/highest scheduled task
  on `ID-DC01`; that local call succeeded.
- Forced Configuration partition replication twice and queried the resulting
  inventory under local SYSTEM on both DCs.

Observed:

- `KdsSvc` was Manual/Stopped under LocalSystem. Starting it left the remote
  call unchanged at `0x80070032`.
- `Get-KdsConfiguration` succeeded and both required Windows features were
  installed, so repair b was not indicated.
- Repair c succeeded locally and returned a KeyId digest, while the same API
  remained unsupported through the remote user context.
- RWDC local SYSTEM observed the root-key inventory. RODC local SYSTEM still
  observed zero keys after two successful Configuration replication calls.

Stop decision:

- Part 2 did not start because the required same-key visibility gate on both
  DCs was not met. All VMs were restored to `dmsa-baseline` and powered off.
