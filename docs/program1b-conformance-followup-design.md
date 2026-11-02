# Program 1b Conformance Follow-up Design

Date: 2026-11-02

## Objective

Program 1b extends the existing Windows Server 2025 identity conformance
evidence without changing the Program 1 standard. It will decide whether the
RODC-local dMSA migration state affects a documented service boundary, whether
Undo/Reset can alter managed-password retrieval authorization without an
explicit grant, whether documented Kerberos events 307-309 are emitted on
build 26100, and which previously unobserved invariants can be exercised in the
current lab.

The final result may contain zero to three discrepancies. An observation is an
anomaly until it has been reproduced from the named baseline checkpoint in two
independent runs.

## Fixed Environment

- Forest: `idlab.test`
- Hosts: `ID-DC01`, `ID-RODC01`, `ID-SRV01`
- Network: private Hyper-V switch `Bluex-Identity`
- Product build: Windows Server 2025 build 26100
- Baseline checkpoint: `dmsa-baseline` on all three VMs
- Linux verification host: Ubuntu VM at `172.28.10.10`

All Windows experiments run through PowerShell Direct. The Ubuntu VM runs the
Python conformance suite and manifest verification. No experiment requires an
external tenant, host, or network endpoint.

## Evidence Model

Each experiment has two independent run identifiers, `run-a` and `run-b`.
Before each run, all three VMs are restored to `dmsa-baseline`, started in
directory-service order, and checked against the known Program 1 graph digests.
Every public record contains only normalized identifiers, timestamps, state
values, Boolean decisions, status codes, build data, checkpoint identifiers,
and source references. Existing redaction checks reject secret-shaped keys and
values before a record is accepted.

The ledger is append-only. A manifest records the ordered record count and
SHA-256 digest. Raw transient captures remain outside version control and are
discarded after their normalized public record has passed validation.

## Experiment Matrix

### 1. RODC-local migration follow-up

For each independent run:

1. Restore and verify the exact baseline.
2. Direct `Start-ADServiceAccountMigration` to `ID-RODC01`.
3. Record the dMSA attributes and replication metadata visible on the RODC and
   RWDC. This identifies the exact local writes rather than inferring them from
   the aggregate state value.
4. Exercise service decisions pinned to the RODC: Kerberos ticket issuance,
   managed-password retrieval eligibility, and group/claims construction where
   the installed interfaces expose a bounded status result.
5. Force full inbound synchronization from `ID-DC01` and resample both views.
6. Apply one reversible password-replication-policy change, resample, and then
   restore the checkpoint.

The conclusion is either `documented_boundary_affected` or `cosmetic_state`.
No boundary effect is inferred from attribute persistence alone.

### 2. Undo/Reset authorization behavior

For each independent run, create the documented migration states, execute Undo
and Reset separately, and record the state, links, SPN, retrieval authorization
descriptor, host-side install status, and normalized retrieval decision. Then
test three orderings from a fresh baseline: re-enrollment before retrieval,
cached host state before re-enrollment, and group-membership change before
retrieval. A different principal is considered authorized only when the
directory attribute or an independent retrieval decision proves it. An outage
without a widened authorization decision is classified as reliability.

### 3. Kerberos events 307-309

The local provider metadata and repository source catalog establish whether the
events are defined for build 26100. Each documented trigger is run twice from a
fresh checkpoint. Records retain provider, event ID, trigger, time window,
event count, and record ID only. A defined event that never appears under its
documented trigger is a telemetry discrepancy; an event that is merely present
in provider metadata without a documented trigger remains an anomaly.

### 4. Previously unobserved invariants

Each of the 16 WIF, token-exchange, and OIDC invariants is classified as:

- `exercised_in_lab`: a bounded local oracle or installed Windows component can
  make the decision;
- `blocked_entra_tenant`: requires a configured Entra tenant and federation;
- `blocked_windows_client`: requires a Windows 11 client;
- `blocked_other`: exact missing product prerequisite is named.

Local oracle evidence is never described as a Windows product observation. The
two PAC parser invariants without ledger records are handled separately as
bounded parser conformance.

### 5. Parser conformance

Only after items 1-4 are complete, extend the existing bounded PAC/Kerberos
property strategies. Any disagreement must be tied to a redacted lab-observed
structure and reproduced twice. Synthetic parser behavior alone is a software
test result, not a product discrepancy.

## Stop and Reporting Rules

Work stops when three discrepancies satisfy the two-run standard, when an exact
missing lab prerequisite prevents further progress, or when the six-hour budget
expires. Progress is checkpointed at least every 45 minutes. The final summary
is limited to two pages and lists discrepancies, anomalies, ruled-out paths,
touched invariant IDs, and Program 2 prerequisites. Each confirmed discrepancy
also receives a self-contained vendor behavior report.
