# Program 1 Detailed Report Design

## Intent

Produce a public-safe, Turkish technical monograph for Program 1 that explains
the Microsoft Identity and Hybrid Trust invariant work in enough depth for an
independent systems engineer to understand the architecture, reproduce the
tests, audit the evidence boundary, and distinguish measured observations from
unassessed product behavior.

The primary artifact is an A4 PDF. Its editable source is a self-contained HTML
template with inline CSS and SVG. A deterministic Python builder reads the
committed invariant catalog, evidence ledger, manifests, generated report, and
Git history, then expands only the data-driven tables and metrics.

## Goals

- Explain the RFC 7523, RFC 8693, OpenID Connect, MS-PAC, Cloud Kerberos Trust,
  and dMSA contracts covered by the repository.
- Include architecture, state-machine, topology, evidence-lifecycle, result,
  coverage, and timeline visualizations.
- Account for all 37 catalog invariants and all 25 normalized observations.
- Record the verified Ubuntu and Windows test results without inflating them
  into product-impact claims.
- Preserve a public-safe boundary: no credentials, reusable identifiers,
  tokens, tickets, raw PAC material, private paths, or full service responses.
- Render the final PDF in the Windows Server 2025 VM and validate it from the
  Ubuntu VM with independent PDF tooling.

## Non-goals

- No claim of a confirmed product defect or hosted-service behavior.
- No CWE or CVSS assignment without independently confirmed behavior and
  impact.
- No live tenant provisioning, Cloud Trust enablement, or directory mutation.
- No replacement of the deterministic machine-readable report already in the
  repository.

## Audience

The report targets identity protocol engineers, Windows/Active Directory
engineers, defensive security reviewers, and maintainers evaluating the
reproducibility and evidence discipline of the work.

## Approaches considered

### 1. Hand-authored word processor document

This gives fast visual control but makes the invariant matrix, observation
counts, and artifact hashes easy to desynchronize from the repository. It also
weakens reproducibility.

### 2. Markdown converted by an external document stack

This is convenient for prose, but the current laboratory does not contain a
pinned Markdown-to-PDF toolchain. Adding a large document dependency stack only
for one report would broaden the build surface.

### 3. Self-contained HTML plus deterministic data expansion

Selected. Chromium/Edge provides high-quality A4 output in the existing
Windows VM. Inline CSS and SVG keep the source reviewable and portable. A small
standard-library builder can derive all repeated facts from committed sources
and fail closed on count or hash mismatches.

## Information architecture

1. Cover, document control, and executive summary.
2. Scope, terminology, evidence classes, and interpretation rules.
3. Formal method and laboratory architecture.
4. Workload identity, JWT assertion, token exchange, and OIDC state machines.
5. MS-PAC structural validation and bounded parsing.
6. dMSA graph lifecycle and Cloud Kerberos Trust prerequisite gates.
7. Test strategy, empirical results, and evidence-chain integrity.
8. Limitations, assessment posture, and engineering recommendations.
9. Appendices containing the full invariant matrix, observation ledger index,
   artifact hashes, commit timeline, reproducibility commands, glossary, and
   source index.

## Visual system

- A4 portrait, dark navy cover and chapter banners, light content surfaces.
- Cyan denotes deterministic specification oracles.
- Amber denotes bounded observation and review attention.
- Green denotes satisfied build/test gates.
- Magenta denotes explicit trust boundaries.
- Slate denotes unassessed or unavailable contexts.
- Diagrams are inline SVG with text equivalents in nearby prose or tables.

## Data and integrity model

The builder consumes only committed files:

- `spec/invariants.yaml`
- `spec/sources.yaml`
- `evidence/evidence.jsonl`
- `evidence/manifest.json`
- `evidence/sources.json`
- `reports/identity-invariants.json`
- local Git history through the reviewed evidence commit

Before rendering it verifies the expected 37 invariants, 25 records, ledger
digest, source-manifest bindings, outcome totals, unique identifiers, HTTPS
source URLs, and public-safe string shapes. The PDF is rendered in
`Bluex-Windows`; `pdfinfo`, `pdftotext`, and rasterized page inspection run in
`Bluex-Ubuntu`.

## Acceptance criteria

- The generated HTML contains every catalog invariant and evidence record.
- Summary totals equal the verified source data: 37 invariants, 25 records,
  148 Ubuntu tests, 50 Windows tests, and 198 total test cases.
- Outcome totals are 5 accept, 1 reject, 10 observe, 6 skip, and 3
  inconclusive.
- No forbidden secret shape or raw laboratory material appears in source,
  HTML, extracted PDF text, or metadata.
- The PDF opens cleanly, has no blank/truncated terminal page, contains a table
  of contents and appendices, and preserves readable diagrams at A4 size.
- The final repository is clean and the report commit carries the exact DCO
  signature required by the workspace.
