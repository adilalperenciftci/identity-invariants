# Program 1b Conformance Follow-up Implementation Plan

Date: 2026-11-02
Branch: `research/program1b-conformance-followup`

## Task 1: Establish a clean baseline

- [x] Run the complete Python suite in the Ubuntu VM.
- [x] Run the existing Windows/Pester lab suite without changing VM state.
- [x] Restore all three `dmsa-baseline` checkpoints and verify Program 1 graph
  digests and secure-channel health.
- [x] Add the first progress checkpoint.

## Task 2: Add Program 1b evidence validation first

- [x] Add failing tests for Program 1b record fields, independent reproduction
  identifiers, allowed classifications, checkpoint identifiers, and manifest
  sealing.
- [x] Verify the tests fail for the missing Program 1b support.
- [x] Add the smallest ledger/report support required for those tests.
- [x] Run the focused tests and then the complete Ubuntu suite.

## Task 3: Reproduce the RODC-local migration observation

- [x] Execute run A from exact baseline and record attribute-level writes.
- [x] Exercise bounded RODC-local service decisions.
- [x] Force full inbound synchronization and resample.
- [x] Apply and revert one password-replication-policy change and resample.
- [x] Restore baseline and repeat independently as run B.
- [x] Classify the observation from evidence, without extrapolation.

## Task 4: Exercise Undo/Reset authorization orderings

- [x] Add failing Pester assertions for the normalized result schema.
- [x] Run Undo and Reset sequences from baseline for run A.
- [x] Test re-enrollment, host-cache, and group-membership orderings. The cache
  path was bounded as blocked because account installation did not complete.
- [x] Restore baseline and repeat independently as run B.
- [x] Classify widened authorization, reliability-only behavior, or no anomaly.

## Task 5: Exercise events 307-309

- [x] Capture local provider definitions and source references.
- [x] Add failing Pester assertions for the event-window record schema.
- [x] Execute migration and permission-enrollment triggers in two independent
  runs. Key fetch did not complete, so event 309 remains unresolved.
- [x] Classify emitted, documented-but-missing, or not documented for this build.

## Task 6: Account for unobserved invariants

- [x] Generate a precise list of invariant IDs without product ledger records.
- [x] Exercise locally reachable decisions twice.
- [x] Record the exact prerequisite for every blocked invariant.
- [x] Keep local oracle evidence distinct from product observation evidence.

## Task 7: Run bounded parser conformance if eligible

- [x] Extend property strategies only after Tasks 3-6 are exhausted.
- [x] Verify the extended properties against the unchanged parser; no parser
  behavior change was needed.
- [x] Reproduce any lab-linked disagreement twice or classify it as a synthetic
  test observation only.

## Task 8: Seal and report

- [x] Update the Program 1b manifest and verify all record digests.
- [x] Write `reports/program1b-summary.md` within two pages.
- [x] Write up to three `reports/vendor/discrepancy-NN.md` reports only for
  discrepancies meeting the two-run standard.
- [x] Run the complete Ubuntu and Windows suites from clean state.
- [x] Review the diff for secret material, unsupported claims, and files outside
  the requested scope.
