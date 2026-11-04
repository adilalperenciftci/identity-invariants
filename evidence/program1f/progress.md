# Program 1f progress

## 20-minute checkpoint - 2026-11-04T01:13:00Z

Tested:

- Restored the three VMs to `dmsa-baseline` and reproduced the Program 1e
  policy, logging, migration, audit, and ticket-refresh state.
- Collected all eight checklist items with redacted text or digests.
- Selected the first indicated single change: create a KDS root key with an
  effective time ten hours in the past.
- Restored all VMs to `dmsa-baseline` after collection and left them off.

Observed:

- `Test-ADServiceAccount` returned false and stated that the dMSA is not a
  Managed Service Account, so that cmdlet is not an affirmative dMSA
  retrieval probe on this build.
- `Get-KdsRootKey` returned zero keys. The dMSA directory state, direct member
  allow entry, secure channel, machine TGT, and time synchronization checks
  were otherwise healthy.
- Event 309 reported a key fetch through the RODC with status `0xC000009A`
  and `Keys Updated: false`.
- The documented backdated KDS key creation was rejected by `ID-DC01` with
  HRESULT `0x80070032`; no condition changed and retrieval remained denied.

Next:

- Seal the diagnostic ledger and report the cause as not found, with the
  missing KDS key identified as the leading but unconfirmed condition and
  the corrective test explicitly blocked.
