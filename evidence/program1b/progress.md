# Program 1b Progress

## 2026-11-02T01:28:55Z

Tested:

- Confirmed a clean `research/program1b-conformance-followup` worktree at
  `50735b94d713320d5c2fab543cb5f9a0db36028c`.
- Confirmed `ID-DC01`, `ID-RODC01`, and `ID-SRV01` are running on the private
  `Bluex-Identity` switch, build 26100, with no default route.
- Confirmed all three exact `dmsa-baseline` checkpoints exist.
- Confirmed the current RWDC and RODC graph digests match the Program 1
  baseline values.
- Ran the Python suite in the Ubuntu VM: 150 passed, 3 skipped.

Observed:

- The repository and lab begin from the documented Program 1 baseline.
- No Program 1b product discrepancy has been claimed.

Next:

- Run the existing Windows/Pester baseline.
- Add test-first validation for Program 1b evidence and reproduction metadata.
- Restore the exact baseline and begin RODC-local migration run A.

## 2026-11-02T01:44:00Z

Tested:

- Ran the existing Windows suite: 50 passed, 0 failed.
- Added the Program 1b evidence envelope and replication-state normalizer by
  first observing 3 focused test failures, then 3 focused passes and 53/53
  full Windows passes.
- Restored all three exact `dmsa-baseline` checkpoints and revalidated the
  RWDC and RODC Program 1 graph digests.
- Completed a pilot RODC-directed migration sequence, forced full inbound
  synchronization, one reversible PRP allow/prepopulate change, a KDC request
  pinned to the RODC, and a managed-account retrieval check pinned through the
  member secure channel.

Observed:

- The RODC-directed Start changed four selected replicated attributes only in
  the RODC view and added two temporary ACL edges; the RWDC view was unchanged.
- Full inbound synchronization reset the RODC state value and temporary ACLs,
  but the reciprocal migration links and legacy superseded state remained in
  the RODC view. The PRP change did not reconcile that partial graph.
- The member obtained a service ticket from the explicitly bound RODC. After
  PRP prepopulation and RODC secure-channel affinity, managed-account install
  was rejected and the retrieval test returned false.
- Events 307-309 are defined in local provider metadata on build 26100; none
  appeared in the pilot window.
- These are single-run pilot observations only. No discrepancy has been
  claimed.

Next:

- Repeat the complete sequence twice from exact baseline, including service
  decisions both before and after the local migration write.
- Seal only the two independent full runs as Program 1b evidence.
- Proceed to Undo/Reset ordering after the RODC conclusion is evidence-backed.

## 2026-11-02T02:13:00Z

Tested:

- Completed independent RODC follow-up runs A and B from exact baseline,
  including service decisions, forced full inbound synchronization, and a
  reversible password-replication-policy change.
- Completed independent Undo/Reset ordering runs A and B, including explicit
  re-enrollment, changed group membership, and the bounded host-cache probe.
- Confirmed provider definitions for events 307-309 and captured two bounded
  event windows covering successful migration and permission-enrollment
  triggers.
- Exercised the 16 previously unledgered WIF, token-exchange, and OIDC rules as
  local specification oracles twice: 49/49 passed in both runs.
- Extended bounded PAC parser properties and ran them twice: 5/5 passed in both
  runs with no disagreement.
- Sealed 42 normalized ledger records and verified manifest SHA-256
  `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33`.

Observed:

- The RODC-local migration graph partially survives full synchronization and
  a PRP change, but did not alter the tested KDC or retrieval decisions. This
  meets the two-run bar as a reliability/documentation discrepancy.
- Events 307 and 308 were absent after their successful documented triggers in
  both runs. This meets the two-run bar as a telemetry discrepancy. Event 309
  remains unresolved because key fetch did not complete.
- Undo/Reset did not widen retrieval authorization. The evidenced consequence
  is reliability-only; host cache was not established on this build.
- No parser disagreement or third product discrepancy met the bar.

Next:

- Restore all three VMs to `dmsa-baseline`.
- Run final full Ubuntu and Windows suites, verify the manifest, and review the
  complete diff for unsupported claims or sensitive material.

## 2026-11-02T02:25:00Z

Tested:

- Verified the sealed Program 1b manifest, all 42 JSONL records, both
  reproduction identifiers, checkpoint bindings, and existing metadata
  redaction rules in the Ubuntu VM.
- Ran `compileall` and the complete Python suite in the Ubuntu VM: 152 passed,
  3 skipped.
- Ran the complete Windows contract suite on `ID-DC01`, the suite's required
  mutation-control context: 53 passed, 0 failed.
- Restored all three exact `dmsa-baseline` checkpoints after testing and
  confirmed the temporary test directories are absent.
- Revalidated final RWDC digest
  `9c19162c8e7d44ad74a1990ef5775f8fdc3b8fe7a3c2fab5e08451c2eb79ae59`
  and RODC digest
  `5be77ff6160d84dcfee8cba5bb935b13f0337492676124a1b02a1e0d4771bfe2`.
- Confirmed state 0 on both DC views, a valid member secure channel, and zero
  default routes on all three hosts.
- Validated all three reports with the repository safety gate, cross-checked
  every discrepancy claim against the sealed ledger, and scanned the complete
  change set for secret-shaped material, raw captures, and out-of-scope files.

Observed:

- Two discrepancies meet the two-run standard: one
  reliability/documentation discrepancy and one telemetry discrepancy.
- No authorization widening, parser disagreement, or third product discrepancy
  met the evidence bar.
- The isolated lab is clean and restored to the Program 1 baseline.

Next:

- Commit the self-contained Program 1b deliverables on the isolated branch.
