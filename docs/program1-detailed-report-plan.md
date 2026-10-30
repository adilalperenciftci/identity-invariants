# Program 1 Detailed Report Implementation Plan

**Goal:** Build and verify an extremely detailed, visual, public-safe Turkish
PDF report from the reviewed Program 1 evidence.

**Architecture:** A deterministic Python builder validates committed sources
and expands a self-contained HTML template. Inline CSS and SVG provide the
visual system. Microsoft Edge renders the PDF in `Bluex-Windows`; Poppler tools
validate and rasterize it in `Bluex-Ubuntu`.

**Design:** `docs/program1-detailed-report-design.md`

## Task 1: Freeze report facts and RED validation

- Add focused tests for catalog count, record count, outcome distribution,
  manifest digest, required sections, visual IDs, and public-safe content.
- Run the tests in Ubuntu and prove RED because the builder/template do not yet
  exist.

## Task 2: Implement the deterministic report model

- Add `tools/build_detailed_report.py`.
- Parse and cross-check catalog, sources, ledger, manifests, generated JSON,
  and Git history.
- Generate escaped invariant, observation, source, hash, and commit rows.
- Emit a compact build-data JSON beside the HTML for independent audit.
- Run focused tests to GREEN in Ubuntu.

## Task 3: Author the visual report template

- Add `reports/program1-detailed-report.template.html` with the complete
  Turkish narrative, print CSS, inline SVG diagrams, and data placeholders.
- Cover the formal model, all protocol areas, laboratory topology, test
  methodology, empirical observations, evidence integrity, limits, and
  recommendations.
- Generate `reports/program1-detailed-report.html` in Ubuntu.
- Verify the complete Python suite remains green.

## Task 4: Render PDF in the Windows VM

- Transfer only the self-contained generated HTML to `Bluex-Windows`.
- Render A4 PDF with headless Microsoft Edge.
- Copy the PDF back to the workspace without exposing credentials or private
  laboratory artifacts.

## Task 5: Validate PDF in the Ubuntu VM

- Run `pdfinfo`, `pdftotext`, and text assertions against the PDF.
- Rasterize representative cover, architecture, protocol, results, and
  appendix pages.
- Inspect the page images for clipping, overlap, tiny type, and broken color.
- Record SHA-256, page count, file size, and extracted-text facts in a public
  verification manifest.

## Task 6: Final regression and commit

- Re-run the 148-test Ubuntu suite and 50-test Windows Pester suite.
- Rebuild the HTML and confirm byte identity.
- Re-render the PDF and confirm stable extracted content and page count.
- Scan tracked files and PDF text for secret shapes.
- Commit the source, generated report, PDF, verification manifest, and design
  documents with the exact DCO signature.
