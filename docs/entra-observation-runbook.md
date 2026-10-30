# Entra and Cloud Kerberos Observation Runbook

## Closed-by-default boundary

The Entra adapter is an observation gate, not a provisioning tool. It permits a request only when one exact tenant is allow-listed, the application is explicitly disposable, the authority host is allow-listed, a federated identity credential identifier is present, no directory role is assigned, the redaction probe has passed, the request ceiling is between one and eight, and the operator supplies a bounded run label. A missing or malformed prerequisite produces a normalized `skip` record before transport invocation.

The Cloud Kerberos gate is read-only. It inventories the isolated forest and never creates an AzureADKerberos object, changes password replication policy, enables Cloud Trust, joins a client, or requests a cloud token. Certificate Trust selection has precedence and therefore yields `skip` instead of being classified as a Cloud Trust observation.

## Entra gate procedure

1. Keep the default closed configuration unless a separately authorized disposable tenant and application are available.
2. Run the current-environment gate in Ubuntu:

   ```text
   PYTHONPATH=src .venv/bin/python -m identity_invariants.adapters.entra evidence/private/task9-current/ubuntu-entra.jsonl --environment ubuntu-lab
   ```

3. Run the same source revision in the Windows Server lab with `PYTHONPATH` pointing to its copied `src` directory and `--environment windows-lab`. Do not install packages or add network connectivity for this check.
4. Verify each generated `.manifest.json`, then confirm `outcome=skip` and `metadata.network_request_count=0` before retaining the ledger.
5. A permitted observation consumes its request budget before transport. Failed transport and malformed responses still consume that ordinal. Once the ceiling is reached, the adapter returns `request_ceiling_reached` without invoking transport.

Only the following response metadata may be retained: run label, authority host, request ordinal, HTTP status, documented error code, a domain-separated SHA-256 digest of the canonical correlation identifier, and elapsed milliseconds. Never retain assertions, tokens, response descriptions, tenant identifiers, application identifiers, credentials, raw correlation identifiers, or complete response bodies. Identifiers used in the input digest are domain-separated SHA-256 values.

## Cloud Kerberos preflight

Run `Test-CloudTrustGate` from `lab/windows/Test-CloudTrustGate.ps1` under an account that can read the lab directory. The gate checks:

- a writable Windows Server 2025 domain controller;
- the exact `AzureADKerberos$` directory object;
- exact references to the allowed and denied RODC password replication policy groups;
- Cloud Trust policy selection without Certificate Trust precedence;
- an enabled, domain-joined Windows 11 client object;
- domain-controller line of sight measured locally on that Windows 11 client; and
- a locally observable partial TGT on that Windows 11 client.

The inventory contains booleans and stable reason codes only. `NetworkRequestCount` must remain zero. An absent client cannot satisfy the partial-TGT check, and a partial TGT is never inferred from directory state.

## Current isolated-lab result

The corrected 2026-10-30 review run retained the two closed Entra ledgers and regenerated the read-only Cloud Kerberos inventory on `ID-DC01` from source commit `4a4524a2068831ad2d744888a7efb257b0f30f3b`.

| Gate | Outcome | Stable reasons | External requests |
| --- | --- | --- | ---: |
| Ubuntu Entra | `skip` | `tenant_context_missing`, `disposable_application_missing`, `authority_host_not_allowed`, `fic_identifier_missing`, `redaction_probe_failed`, `request_ceiling_invalid`, `run_label_missing` | 0 |
| Windows Entra | `skip` | Same closed-environment reasons as Ubuntu | 0 |
| Cloud Kerberos | `skip` | `cloud_kerberos_object_missing`, `password_replication_policy_unverified`, `cloud_trust_policy_unverified`, `windows_11_client_missing`, `line_of_sight_missing`, `partial_tgt_missing` | 0 |

The local forest satisfied the Server 2025 RWDC check. Because the read-only run executed on `ID-DC01` rather than `ID-CL01`, `LineOfSight` remained false without a domain probe and the result records `line_of_sight_missing`. Certificate Trust was not selected. No cloud state was provisioned and no external endpoint was contacted. The normalized Cloud artifact SHA-256 is `464736fc7f5fe25bc775ef1e4097f23556f31775a5b912e7b44134a504cd6af0`; its separate manifest SHA-256 is `ad456eace6634f97719982963e31f372ffa16bb917409b27255b9339188946fd`.

## Evidence and cleanup

Write Entra records through `EvidenceWriter`; serialize the Cloud gate as one bounded canonical JSON artifact with its own digest manifest. Verify every manifest in Ubuntu. Retain no raw response body or token-shaped value. Copy only sealed, normalized evidence out of a VM. Restore all identity VMs to the exact `dmsa-baseline` checkpoints after the final run and revalidate AD Web Services, the member secure channel, and baseline graph digests.
