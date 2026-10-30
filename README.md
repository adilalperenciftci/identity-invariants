# Microsoft Identity Protocol Invariants

This repository turns selected Microsoft identity protocol requirements into
deterministic, typed checks and bounded laboratory observations. Its current
scope covers workload identity federation, OAuth 2.0 token exchange, OpenID
Connect, Cloud Kerberos Trust preconditions, MS-PAC parsing, and delegated
managed service account lifecycle state.

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

## Current bounded result

The catalog contains 37 source-linked invariants. The public evidence index
contains 25 normalized Windows and closed-environment observations:

- dMSA state, reciprocal-link, temporary-ACL, enrollment, transfer, RODC, and
  checkpoint restoration observations are recorded; supported event emission
  remains inconclusive for the exercised windows.
- RWDC- and RODC-issued service tickets were decoded through the bounded PAC
  parser. Signature roles and the RODC identifier were observed. Requestor
  binding in an encrypted TGT remains unassessed.
- Live Entra and Cloud Kerberos behavior is not claimed. Both paths are marked
  `skip` because their required disposable tenant and Windows 11 client context
  were absent; their external request count remained zero.
- CWE and CVSS are `not assessed`. Local oracle behavior and laboratory
  observations are not statements about hosted product impact.

See the [generated evidence report](reports/identity-invariants.md) for the
source-to-invariant matrix and exact artifact hashes.

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
