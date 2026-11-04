# Program 1f managed-password retrieval diagnosis

## Question and classification

Program 1f asked which documented prerequisite or directory condition causes
the member's dMSA managed-password retrieval to fail, and whether correcting
that one condition makes service sign-in succeed.

The cause was **not found**. The checklist identified one clear prerequisite
failure: the forest contained no KDS root key. That is the leading condition,
but it is not a confirmed cause because the prescribed single change could
not be applied. `Add-KdsRootKey` with a ten-hour backdated effective time was
rejected on `ID-DC01` with HRESULT `0x80070032` (request not supported). The
directory therefore did not change, retrieval remained denied, and no
second reproduction or post-fix sign-in was possible.

## Starting state

The run began from `dmsa-baseline` and reproduced the Program 1e end state.
The member policy read back as 1, the Operational log was enabled, the secure
channel was valid, Start migration against `ID-DC01` produced state 1, and
replication returned exit 0. The pre-change SCM start again returned 1069.

## Checklist

| Item | Observed value or digest | Verdict |
| --- | --- | --- |
| 1. `Test-ADServiceAccount` | `false`; redacted warning: "The `<dmsa>` is not a Managed Service Account. Verify the identity and call the cmdlet again." | The cmdlet is not an affirmative dMSA retrieval probe on this build |
| 2. KDS root key | Count `0` at `2026-11-04T01:12:01.6128123Z` | Failed prerequisite; leading unconfirmed condition |
| 3. dMSA directory state | Membership digest `7bbcac59c22286822b8466804dd9b637f0e35e506d3cbe28a58d0a8131704e07`; one directly allowed member SID; interval 30 days; dMSA state 1; legacy superseded state 1; UAC 4096; enabled; not expired | Consistent with the documented post-Start state |
| 4. Member secure channel | `nltest` exit 0; bound to RWDC; `Test-ComputerSecureChannel=true`; output digest `a5a125d0a0066bb05da1dc68eb00b1e266926d09ecb9da3925e3362426ba43a5` | Healthy; change c not indicated |
| 5. Member Kerberos state | `klist` exit 0; machine TGT present; digest `539763723a8947cf597d8a306004ff660586466d9c085be4d5a4d6ba4c1a7a10`; Credential Guard running; no KDC proxy configuration | TGT present; no failed prerequisite established |
| 6. Time skew | Member-to-RWDC `-0.3965426` seconds; member-to-RODC `-0.3966179` seconds | Within normal tolerance |
| 7. Event 309 | One record; KDC role RODC; `Keys Updated: false`; `Ntlm Updated: false`; status `0xC000009A`; message digest `586b757b601a0e6dada2594c84967b152dba2a98aad962eab562d8e131829882` | Confirms failed client key fetch; it does not identify the cause by itself |
| 8. RWDC Security log | One member 4768 record with status `0x0`; no matching dMSA result record | Member TGT path succeeded; no dMSA-side result code was available |

Event 309 selected the RODC as KDC even though the member secure channel was
healthy and bound to the RWDC. Secure-channel affinity and Kerberos KDC
selection are therefore not treated as equivalent observations.

## Single-change test

| Change | Application result | Retrieval result | Service result |
| --- | --- | --- | --- |
| a. Create a KDS root key with an effective time ten hours in the past | Blocked: `Add-KdsRootKey` returned `0x80070032`; key count remained 0 | Denied, unchanged | Not run because the requested condition was not applied |

Changes b and c were not indicated: the member was directly present in the
allow descriptor and its secure channel was healthy and RWDC-bound. Change d
was not indicated because the dMSA was enabled, unexpired, and in state 1.
No later change was attempted after the first indicated correction was
blocked.

## Evidence

The diagnostic collection window ran from
`2026-11-04T01:10:00.7127907Z` through
`2026-11-04T01:12:05.4443713Z`. The sealed ten-record ledger SHA-256 is
`2d4148baefd3cd718e43d4557a6e636372cdac5fef31ce5b9d7e251126b06807`.

## Conclusion

Program 1f did not establish a cause. The missing KDS root key is the first
failed documented prerequisite and the strongest measured lead, while the
directory allow entry, migration state, secure channel, machine TGT, and time
synchronization checks passed. Because the prescribed KDS correction was
rejected before it changed the directory, retrieval could not be re-tested
under the corrected condition and causality could not be reproduced.
Program 1e should not be re-run until the lab can create and replicate the
documented KDS root key from the same baseline.

Program 1g later showed that `0x80070032` was invocation-context dependent:
the remote domain-user call failed while the same backdated call succeeded
under local SYSTEM on `ID-DC01`; RODC visibility still did not follow.
