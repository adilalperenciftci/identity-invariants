# Program 1d enforcement check

## Question and classification

Program 1d asked whether the S1 RODC-local `WriteProperty` right for
`msDS-GroupMSAMembership` can be enforced by the legacy principal and whether
an accepted write changes a decision presented to the member server.

The classification is **not enforceable**. In both independent runs, direct
RODC attempt 1a returned LDAP referral result 10, referral-following attempt
1b ended with insufficient-access result 50, and direct RWDC attempt 1c also
returned result 50. Neither DC's attribute digest changed after any attempt.
Program 1c discrepancy-03 is therefore reclassified as authorization-data
consistency / documentation, and the RODC enforcement line is closed.

## Procedure

Each run began from `dmsa-baseline`. Start migration was directed to
`ID-RODC01`, and the S1 descriptor cell was required to match
`116a345a16a0dfe8084dc0da8c2a29a6a3c7b10ee71d5ca14c1a4349b748ef8d`
before collection. The legacy identity then issued three LDAP replace
requests for a byte-distinct security descriptor that retained the existing
member allow entry and added a second member allow ACE. Only the intended
value digest was retained. Readback followed each attempt. SCM service start
and managed-retrieval observations were taken before and after the attempts,
then explicit full inbound replication produced S2 and cleanup was checked.

The quoted times below are ledger observation-collection windows, not the
full run duration. Checkpoint restore and S1 transition preceded each window;
S2 replication completed before the corresponding records were normalized
and sealed.

- Run A: `2026-11-03T23:36:15.8534239Z` through
  `2026-11-03T23:36:38.5617442Z`.
- Run B: `2026-11-03T23:39:21.1082465Z` through
  `2026-11-03T23:39:43.2678756Z`.

## Results

| Observable | Cell | Run A result | Run A digest | Run B result | Run B digest |
|---|---|---|---|---|---|
| Write | 1a | referral / LDAP 10 | `6b6a309cae942b7f9dc24cc04f0c72558a7980643dcf87ed2da5d83afeca6bab` | referral / LDAP 10 | `6b6a309cae942b7f9dc24cc04f0c72558a7980643dcf87ed2da5d83afeca6bab` |
| Write | 1b | denied / LDAP 50 | `d7ad7cb5d982b21c3d1691f5b7098ca20dd362e0f74ff1348a70db7266799f53` | denied / LDAP 50 | `d7ad7cb5d982b21c3d1691f5b7098ca20dd362e0f74ff1348a70db7266799f53` |
| Write | 1c | denied / LDAP 50 | `0efb678d5541e47ccd909971fc8be7a76ceb5416605e7ee2b9f56047cdb925c5` | denied / LDAP 50 | `0efb678d5541e47ccd909971fc8be7a76ceb5416605e7ee2b9f56047cdb925c5` |
| dMSA service | Before | blocked: RODC affinity | `be1d7c1ebdc25bbdf9491871310f018fce4ff1717f73e2dbacfb362936817188` | blocked: RODC affinity | `be1d7c1ebdc25bbdf9491871310f018fce4ff1717f73e2dbacfb362936817188` |
| dMSA service | After | blocked: RODC affinity | `3a9d4bb884ae862d163c4d5ece9c87ba450b9774fadeba3090874301bbad0940` | blocked: RODC affinity | `3a9d4bb884ae862d163c4d5ece9c87ba450b9774fadeba3090874301bbad0940` |
| Retrieval | Before / RODC | blocked: RODC affinity | `f9976e4338edda727a1b894d8d1e21f3b92db8cf29865d587887a523c1371b25` | blocked: RODC affinity | `f9976e4338edda727a1b894d8d1e21f3b92db8cf29865d587887a523c1371b25` |
| Retrieval | Before / RWDC | denied | `5858a9c7c85f184a8889c968ead458aa1143d6d607a9f19c9bd0117d1c0c9367` | denied | `5858a9c7c85f184a8889c968ead458aa1143d6d607a9f19c9bd0117d1c0c9367` |
| Retrieval | After / RODC | blocked: RODC affinity | `074a75cad0d5a4b663fdb4a2d60ef0119bc5b1091a0581584a3b4cc4835400d7` | blocked: RODC affinity | `074a75cad0d5a4b663fdb4a2d60ef0119bc5b1091a0581584a3b4cc4835400d7` |
| Retrieval | After / RWDC | denied | `83251716aca84117499d00c0ea34bf6f4d60a228b1587fc88a43767248764534` | denied | `83251716aca84117499d00c0ea34bf6f4d60a228b1587fc88a43767248764534` |
| Cleanup | RWDC | original value | `60fc3516c63f66aea3ce3eb59c1244ec6e7d8bfd1d40499e1b5382288b9aea23` | original value | `60fc3516c63f66aea3ce3eb59c1244ec6e7d8bfd1d40499e1b5382288b9aea23` |
| Cleanup | RODC | original value | `594430557a0209ca5dbcae2fb75921abaae6f94991714d3bd19bcf15745e7f06` | original value | `594430557a0209ca5dbcae2fb75921abaae6f94991714d3bd19bcf15745e7f06` |

Attempt 1a returned the same referral-target digest in both runs:
`8d9812e6547088975062e60ed3829a5c5d33f78915539d97cff9332a84abe8fa`.
SCM successfully created the dMSA service before and after each write window,
but start returned 1069 and Security recorded event 4625. Because secure
channel reset to the RODC returned exit 1, those service observations and the
RODC retrieval cells are explicitly blocked rather than attributed to the
RODC. RWDC retrieval was false before and after in both runs.

## Conclusion

The RODC-local ACE is authorization metadata that does not yield a local RODC
write. Direct modification is referred, referral following reaches a denied
decision, and the authoritative RWDC denies the same request. No intended
attribute value appeared in either view, and S2 cleanup retained only the
original value. The measured result closes discrepancy-03 as an
authorization-data consistency / documentation discrepancy. The RODC-pinned
dMSA service and retrieval sub-observables remain blocked because the member
secure channel could not be reset to the RODC; no claim is made for those
unobtained decisions.

The sealed eight-record ledger SHA-256 is
`bef7d3da03b4c0df2793976efd0aa29972e33503095f67c894e61fd3e4ce5ab4`.
