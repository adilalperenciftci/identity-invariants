# Microsoft Identity Protocol Invariants

This repository turns selected Microsoft identity protocol requirements into
deterministic, typed checks and bounded laboratory observations. Its current
scope covers workload identity federation, OAuth 2.0 token exchange, OpenID
Connect, Cloud Kerberos Trust preconditions, MS-PAC parsing, and delegated
managed service account lifecycle state.

**Merged repository totals:** 37 source-linked invariants, 85 normalized
evidence records (25 from Program 1, 42 from Program 1b, 10 from Program 1c,
and 8 from Program 1d), and 208 collected test cases (155 Python and 53
Pester).

The project separates four evidence classes:

- `spec-oracle`: deterministic decisions derived from public protocol rules;
- `local-adapter`: normalized output from a local implementation boundary;
- `windows-observation`: bounded observations from the isolated Server 2025
  identity lab;
- `entra-observation`: closed-by-default observations that require an
  explicitly allow-listed disposable tenant context.

An `accept`, `reject`, or `observe` result has meaning only inside its stated
evidence class. A `skip` records an unmet prerequisite without contacting an
external service. An `inconclusive` result preserves an observation boundary
that the available evidence cannot resolve.

## Safety boundary

The committed evidence tree contains normalized reason codes, environment
descriptions, and SHA-256 digests only. It must never contain signed
assertions, access tokens, Kerberos tickets, packet payloads, private keys,
directory credentials, reusable identifiers, or complete service responses.
Raw laboratory material remains in ignored `evidence/private/` storage and is
removed after normalization and checkpoint restoration.

The Entra adapter cannot provision resources. Its gate closes before transport
unless every tenant, application, authority, request-budget, redaction, and run
label prerequisite is satisfied. The Cloud Kerberos gate is read-only and does
not create directory objects, change password replication policy, enable trust
policy, or join a client.

## Reproduce on Ubuntu

Use Python 3.12 in the isolated Ubuntu laboratory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
PYTHONPATH=src .venv/bin/python -m pytest -q
PYTHONPATH=src .venv/bin/python -m compileall -q src tests
PYTHONPATH=src .venv/bin/python -m identity_invariants.reports.render \
  --verify-only evidence/manifest.json
```

Regenerate the deterministic public report only from a verified manifest:

```sh
PYTHONPATH=src .venv/bin/python -m identity_invariants.reports.render \
  --render evidence/manifest.json \
  --catalog spec/invariants.yaml \
  --output reports/identity-invariants.md
```

The integration gate compares the regenerated Markdown and JSON byte-for-byte
with the committed report.

## Program 1 results

The catalog contains 37 source-linked invariants. The public evidence index
contains 25 normalized Windows and closed-environment observations:

- dMSA state, reciprocal-link, temporary-ACL, enrollment, transfer, RODC, and
  checkpoint restoration observations are recorded. The build-created account
  remained in state `0`; documented standalone state `3` was not observed.
  Undo and Reset restored state and links but cleared machine enrollment, so
  only exact checkpoint restoration reproduced the baseline digest.
- Supported dMSA event emission remains inconclusive for the exercised direct
  service logon, local-system ticket refresh, and Service Control Manager
  windows.
- RWDC- and RODC-issued service tickets were decoded through the bounded PAC
  parser. Signature roles and the RODC identifier were observed. Requestor
  binding in an encrypted TGT remains unassessed.
- Live Entra and Cloud Kerberos behavior is not claimed. Both paths are marked
  `skip` because their required disposable tenant and Windows 11 client context
  were absent. Client line of sight and a partial TGT were not inferred from
  RWDC-local state; their external request count remained zero.
- CWE and CVSS are `not assessed`. Local oracle behavior and laboratory
  observations are not statements about hosted product impact.

See the [generated evidence report](reports/identity-invariants.md) for the
source-to-invariant matrix and exact artifact hashes.

The 40-page [detailed visual report](reports/program1-detailed-report.pdf)
combines the formal model, laboratory topology, trust-boundary state machines,
complete invariant and observation matrices, evidence lineage, limitations,
and prioritized engineering recommendations. Its self-contained
[HTML edition](reports/program1-detailed-report.html),
[machine-readable data](reports/program1-detailed-report-data.json), and
[verification manifest](reports/program1-detailed-report-verification.json)
are committed beside the PDF for independent review.

## Program 1b

Program 1b repeated and extended the incomplete dMSA checks from the same
isolated baseline. Two documented-vs-observed discrepancies met the required
two-run standard: one reliability/documentation discrepancy in an RODC-local
migration graph and one telemetry discrepancy for absent events 307 and 308.
No authorization or confidentiality boundary change was observed.

| ID | Category | Report |
| --- | --- | --- |
| `discrepancy-01` | Reliability/documentation | [RODC-directed migration graph](reports/vendor/discrepancy-01.md) |
| `discrepancy-02` | Telemetry | [Missing dMSA events 307 and 308](reports/vendor/discrepancy-02.md) |

The merged suite collects 155 Python tests and 53 Pester tests. The Program 1b
verification recorded 152 Python passes with 3 skips and 53 Pester passes.

### Submission status

- `discrepancy-01`: ready for Feedback Hub; the documentation channels that
  accept unauthenticated submissions (Learn page feedback, the docs
  repository) require a signed-in Microsoft account or prior-contributor
  status, so submission is a manual step
- `discrepancy-02`: on hold, not to be submitted in its current form. The
  Program 1b event windows did not confirm that the
  `Microsoft-Windows-Kerberos/Operational` log was enabled on all three
  hosts, and the member server never completed a dMSA sign-in because the
  documented `DelegatedMSAEnabled` client policy was not configured. Events
  307-309 are written by the Kerberos client of the machine that signs in
  with the dMSA, so their absence is not evidence until that path works.
  Re-validation is a separate program
- `discrepancy-03`: ready for Feedback Hub together with `discrepancy-01`
  (same RODC migration path, consistency/documentation category)

## Program 1c

Program 1c answered the authorization question left open by Program 1b. Two
independent checkpoint runs found one boundary discrepancy: during S1, the
RODC-local dMSA descriptor grants the legacy service-account principal the
`msDS-GroupMSAMembership` write right while the authoritative RWDC descriptor
does not. No service-logon, group-membership, managed-retrieval, or member
computer effective-access decision changed. Full inbound synchronization
removed the temporary right in S2.

| ID | Category | Report |
| --- | --- | --- |
| `discrepancy-03` | Authorization-data consistency/documentation | [RODC-local non-authoritative object right](reports/vendor/discrepancy-03.md) |

The Program 1c ledger adds 10 normalized records. The complete five-observable
digest matrix and the single blocked sub-observable are documented in the
[Program 1c closure report](reports/program1c-closure.md).

### Submission status

- `discrepancy-03`: prepared, not yet submitted

## Program 1d

Program 1d tested whether discrepancy-03's RODC-local right is enforceable.
Two checkpoint runs produced the same result: the direct RODC write was
referred, referral following was denied, and the RWDC denied the request
directly. Neither directory view changed, and S2 retained only the original
attribute value. Discrepancy-03 is reclassified as authorization-data
consistency / documentation and the enforcement line is closed.

The [Program 1d closure report](reports/program1d-closure.md) contains the
three LDAP results, downstream observation limits, cleanup state, and the
sealed eight-record evidence digest.

## Repository map

- `spec/`: invariant catalog, source metadata, and schema;
- `src/identity_invariants/oracle/`: typed OIDC, JWT assertion, and token
  exchange state machines;
- `src/identity_invariants/pac/`: bounded MS-PAC structure parser;
- `src/identity_invariants/adapters/`: Windows and closed Entra observation
  boundaries;
- `src/identity_invariants/evidence/`: canonical append-only ledger and
  manifest verification;
- `src/identity_invariants/reports/`: deterministic report renderer and safety
  validation;
- `lab/windows/`: plan-first topology, dMSA, PAC, and Cloud Kerberos gates;
- `tests/`: unit, property, integration, and PowerShell contract tests;
- `docs/`: architecture, evidence dictionary, and laboratory runbooks.

The detailed trust model is documented in
[docs/architecture.md](docs/architecture.md). Laboratory operation and exact
restore gates are documented in [docs/lab-runbook.md](docs/lab-runbook.md).
