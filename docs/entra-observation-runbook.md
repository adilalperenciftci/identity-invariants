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

The 2026-10-30 run used the Task 9 source revision in Ubuntu and `ID-SRV01`, plus the read-only Cloud Kerberos inventory on `ID-DC01`.

| Gate | Outcome | Stable reasons | External requests |
| --- | --- | --- | ---: |
| Ubuntu Entra | `skip` | `tenant_context_missing`, `disposable_application_missing`, `authority_host_not_allowed`, `fic_identifier_missing`, `redaction_probe_failed`, `request_ceiling_invalid`, `run_label_missing` | 0 |
| Windows Entra | `skip` | Same closed-environment reasons as Ubuntu | 0 |
| Cloud Kerberos | `skip` | `cloud_kerberos_object_missing`, `password_replication_policy_unverified`, `cloud_trust_policy_unverified`, `windows_11_client_missing`, `partial_tgt_missing` | 0 |

The local forest did satisfy the Server 2025 RWDC check. The read-only run executed on `ID-DC01`, so it did not claim client-local line of sight. Certificate Trust was not selected. No cloud state was provisioned and no external endpoint was contacted.

## Evidence and cleanup

Write normalized records through `EvidenceWriter`, seal the JSONL ledger, and verify the manifest in Ubuntu. Retain no raw response body or token-shaped value. Copy only sealed, normalized evidence out of a VM. Restore all identity VMs to the exact `dmsa-baseline` checkpoints after the final run and revalidate AD Web Services, the member secure channel, and baseline graph digests.
