# Program 1b through Program 1f vendor report index

These reports describe documented-vs-observed behavior from the isolated
Windows Server 2025 build 26100 lab. Program 1b reports do not claim an
authorization or confidentiality boundary change. Program 1c reports the
bounded authorization-data difference reproduced by the Windows Authz check.

| ID | Title | Category | Status | Evidence case IDs | Ledger digest |
| --- | --- | --- | --- | --- | --- |
| `discrepancy-01` | [RODC-directed dMSA migration leaves a partial local graph](discrepancy-01.md) | Reliability/documentation | Ready for Feedback Hub (manual submission) | `dmsa-rodc-convergence-run-a`<br>`dmsa-rodc-convergence-run-b` | `c9855af1af16aa2f2367ac64d0d93d5863eb7709218c75588afa2c349b296a33` |
| `discrepancy-02` | [dMSA client event behavior requires successful sign-in re-validation](discrepancy-02.md) | Potential telemetry | On hold: Program 1f found no KDS root key, but the corrective creation was blocked by `0x80070032`; cause remains unconfirmed | `program1e-service-sign-in-run-a`<br>`program1e-kerberos-events-run-a`<br>`program1f-check-02-kds-root`<br>`program1f-single-change-a` | `610aaac1fd6f1d9d36e45ebf02534c79cdb08b7b0d7726c98f5c7dc77541a8df`<br>`2d4148baefd3cd718e43d4557a6e636372cdac5fef31ce5b9d7e251126b06807` |
| `discrepancy-03` | [RODC-local dMSA migration grants a non-authoritative object right](discrepancy-03.md) | Authorization-data consistency/documentation | Ready for Feedback Hub (manual submission) | `program1c-effective-access-run-a`<br>`program1c-effective-access-run-b`<br>`program1d-write-attempts-run-a`<br>`program1d-write-attempts-run-b` | `0c0955044d96cb4db1b81efcdd9cec8def4b10d70d7b8d82fe85c690e1cde0ac`<br>`bef7d3da03b4c0df2793976efd0aa29972e33503095f67c894e61fd3e4ce5ab4` |

The digest identifies the sealed 42-record Program 1b ledger described by
[`evidence/program1b/manifest.json`](../../evidence/program1b/manifest.json).
The Program 1c digest identifies its sealed 10-record ledger described by
[`evidence/program1c/manifest.json`](../../evidence/program1c/manifest.json).
The Program 1d digest identifies its sealed 8-record ledger described by
[`evidence/program1d/manifest.json`](../../evidence/program1d/manifest.json).
The Program 1e digest identifies its sealed 10-record ledger described by
[`evidence/program1e/manifest.json`](../../evidence/program1e/manifest.json).
The Program 1f digest identifies its sealed 10-record diagnostic ledger
described by
[`evidence/program1f/manifest.json`](../../evidence/program1f/manifest.json).
