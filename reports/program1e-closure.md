# Program 1e dMSA client path and event re-validation

## Question and classification

Program 1e asked whether a service running as the dMSA signs in on
`ID-SRV01` after the documented client policy is configured, and whether
events 307, 308, and 309 appear on the machine that performs that sign-in.

The classification is **blocked**. In both independent runs the client policy
was present after restart, every Kerberos Operational log was enabled before
the event window, and Start migration against the writable DC completed.
The SCM service start nevertheless returned 1069. Security recorded event
4625 with logon type 5, status `0xc000009a`, and substatus `0x0`; it recorded
no 4624 success. The event-absence question therefore remains unresolved and
discrepancy-02 stays on hold.

## Procedure followed

Each run began with an independent restore of all three VMs to
`dmsa-baseline`. The Kerberos Operational log was enabled on `ID-DC01`,
`ID-RODC01`, and `ID-SRV01`, then read back before any state change. On the
member, `DelegatedMSAEnabled` was written as DWORD `1`. A restart was
performed in both runs, after which the value, log state, and secure channel
were read back successfully.

Start migration was directed to `ID-DC01`. The resulting state was 1 in both
DC views with one predecessor link and one enrolled principal. Full inbound
replication to the RODC returned exit 0. The member's machine tickets were
purged, SCM created the temporary service with an empty password field, and
the service was started under the dMSA identity. Security records and the
three Kerberos Operational logs were then collected inside the bounded
window. The temporary service was deleted after the attempt.

The RODC secure-channel reset returned exit 1 in both runs. The RODC-pinned
service and retrieval cells were therefore marked blocked rather than being
attributed to the RODC. After Run B all three VMs were restored once more to
`dmsa-baseline` and left powered off.

## Per-host log verification

| Run | Host | Enabled before window | Records at open | Enabled at close | Records at close |
| --- | --- | --- | ---: | --- | ---: |
| A | `ID-DC01` | yes | 230 | yes | 230 |
| A | `ID-RODC01` | yes | 615 | yes | 618 |
| A | `ID-SRV01` | yes | 14 | yes | 27 |
| B | `ID-DC01` | yes | 242 | yes | 242 |
| B | `ID-RODC01` | yes | 640 | yes | 640 |
| B | `ID-SRV01` | yes | 14 | yes | 28 |

The member log remained enabled after each restart. Its post-restart record
count was 26 in both runs.

## Four-observable result matrix

| Observable | Run A | Run B |
| --- | --- | --- |
| 1. dMSA service sign-in | RWDC path: SCM 1069; Security 4625, type 5, status `0xc000009a`, substatus `0x0`; no 4624. RODC path blocked by pin exit 1 | Same result |
| 2. Events 307/308/309 | RWDC `0/0/0`; RODC `0/0/0`; member `0/0/1` | RWDC `0/0/0`; RODC `0/0/0`; member `0/0/1` |
| 3. Group membership | No 4627 because the service sign-in failed | No 4627 because the service sign-in failed |
| 4. Managed retrieval | RWDC false before and after; RODC cells blocked by pin exit 1 | Same result |

## Event counts and digests

| Run | Host | 307 | 308 | 309 | 309 normalized-text digest |
| --- | --- | ---: | ---: | ---: | --- |
| A | `ID-DC01` | 0 | 0 | 0 | - |
| A | `ID-RODC01` | 0 | 0 | 0 | - |
| A | `ID-SRV01` | 0 | 0 | 1 | `2525edcab192666e3e87afc0209718d648d7bfe248f04ce1f02aff8e4c363d40` |
| B | `ID-DC01` | 0 | 0 | 0 | - |
| B | `ID-RODC01` | 0 | 0 | 0 | - |
| B | `ID-SRV01` | 0 | 0 | 1 | `a87cad51205fc1cb230e60c348a91ded5341a41fc73d91c6184f86c9a1beb510` |

An event 309 record appeared on the client in each failed sign-in window.
That observation does not satisfy the decision rule because the dMSA sign-in
did not complete. No conclusion is drawn from the zero 307 and 308 counts.

## Evidence windows

- Run A: `2026-11-04T00:28:18.9596257Z` through
  `2026-11-04T00:28:57.3916177Z`.
- Run B: `2026-11-04T00:30:54.9047906Z` through
  `2026-11-04T00:31:34.9695780Z`.

The sealed ten-record ledger SHA-256 is
`610aaac1fd6f1d9d36e45ebf02534c79cdb08b7b0d7726c98f5c7dc77541a8df`.

## Conclusion

The documented client policy and log prerequisites were established in two
independent runs, but the dMSA service did not sign in. Both attempts reached
the Kerberos client path far enough to emit event 309, then ended with the
same SCM and Security failure. Because a successful sign-in was not obtained,
Program 1e neither confirms nor disproves the documented 307/308 event
behavior. Discrepancy-02 remains on hold, the dMSA group cell remains blocked,
and the RODC-pinned cells remain blocked by the separate secure-channel pin
failure.
