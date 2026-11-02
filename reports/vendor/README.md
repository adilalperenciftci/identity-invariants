# Program 1b vendor report index

Both reports describe documented-vs-observed behavior from the isolated
Windows Server 2025 build 26100 lab. Neither report claims an authorization or
confidentiality boundary change.

| ID | Title | Category | Status | Evidence case IDs | Ledger digest |
| --- | --- | --- | --- | --- | --- |
| `discrepancy-01` | [RODC-directed dMSA migration leaves a partial local graph](discrepancy-01.md) | Reliability/documentation | Prepared, not yet submitted | `dmsa-rodc-convergence-run-a`<br>`dmsa-rodc-convergence-run-b` | `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33` |
| `discrepancy-02` | [Documented dMSA migration and permission events are absent](discrepancy-02.md) | Telemetry | Prepared, not yet submitted | `dmsa-documented-events-run-a`<br>`dmsa-documented-events-run-b` | `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33` |

The digest identifies the sealed 42-record Program 1b ledger described by
[`evidence/program1b/manifest.json`](../../evidence/program1b/manifest.json).
