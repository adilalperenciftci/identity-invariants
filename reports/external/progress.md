# Program 1b External Write-ups Progress

## 2026-11-02T06:04:38Z

Completed:

- Created a new worktree from `main` at
  `678ee79f99908595053608c83c6d45eb88867480` on branch
  `research/program1b-external`.
- Confirmed the merged totals by direct enumeration: 37 invariants, 67
  normalized evidence records, and 208 collected test cases (155 Python and
  53 Pester).
- Verified the Program 1b manifest contains 42 records from `run-a` and
  `run-b`, sealed with ledger SHA-256
  `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33`.
- Read the four evidence records supporting the two external write-ups and
  confirmed their categories, case IDs, build, checkpoint, event counts, and
  explicit absence of an observed security-boundary change.
- Ran the unmodified Python suite on the available Windows host: 151 passed,
  3 skipped, and 1 pre-existing platform-specific failure. The failing test
  hashes LF bytes before Windows writes CRLF bytes and therefore stops at a
  ledger-digest mismatch before its intended assertion.

Next:

- Draft the Learn feedback, Feedback Hub entry, technical blog, README
  section, and vendor report index using only sealed evidence.
- Check word limits, relative links, quoted digests, quoted timestamps, and
  documentation consistency.
- Re-run the suite and repository checks before committing and pushing.

## 2026-11-02T06:11:04Z

Completed:

- Drafted the Microsoft Learn feedback (239 words), Feedback Hub entry (346
  words), and technical blog (1,091 words).
- Added the Program 1b README section and vendor report index with verified
  repository totals and submission status.
- Verified every relative link in the new and modified public documents.
- Cross-checked every quoted evidence timestamp, case ID, and ledger digest
  against the sealed Program 1b records and manifest.
- Ran the repository safety validator on all new public documents and confirmed
  that no evidence file changed.
- Ran the full Python suite on the Windows host: 151 passed, 3 skipped, and the
  same 1 pre-existing LF/CRLF platform failure remained. Excluding only that
  platform-specific test, 151 passed, 3 skipped, and 1 was deselected.
- Ran the 53 Pester contracts without contacting the lab. Process-local stubs
  supplied the five ActiveDirectory command names that the tests mock; all 53
  passed.

Next:

- Review and commit the documentation-only diff.
- Verify commit metadata, push `research/program1b-external`, and open the
  requested pull request against `main`.
