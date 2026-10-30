# Evidence Dictionary

The ledger contains normalized protocol decisions only. It never stores signed assertions, access credentials, Kerberos tickets, private keys, packet payloads, or directory secrets.

| Field | Meaning | Persistence rule |
| --- | --- | --- |
| `case_id` | Deterministic generated case identity | Stable, non-secret string |
| `rule_id` | Invariant catalog identifier | Must exist in the catalog |
| `outcome` | `accept`, `reject`, `observe`, `skip`, or `inconclusive` | Normalized enum |
| `reason` | Stable machine-readable reason | Normalized enum |
| `evidence_class` | Oracle or observation boundary | Normalized enum |
| `input_digest` | SHA-256 of canonical normalized input | Lowercase digest only |
| `artifact_digests` | Named SHA-256 values for derived artifacts | Digests only |
| `metadata` | Bounded non-secret measurement context | Recursive redaction gate |

The manifest binds the ledger filename, exact byte digest, record count, and format version. Verification fails if ledger bytes or line count change.
