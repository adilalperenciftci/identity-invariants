# Microsoft Identity Protocol Invariant Evidence

## Assessment status

- CWE: `not assessed`
- CVSS: `not assessed`

## Evidence manifest

- Ledger: `evidence.jsonl`
- Ledger SHA-256: `ebb62eb6075fac1e52a3d8075c16dab6ec2c58b827a95c6709922f15df099a8f`
- Record count: `20`

## Environment fingerprint

| Component | Fingerprint |
| --- | --- |
| seed | 20261030 |
| topology | ID-DC01, ID-RODC01, and ID-SRV01 on private Bluex-Identity; no default route |
| ubuntu | Ubuntu 24.04.5 LTS; Python 3.12.3 |
| windows | Windows Server 2025 build 26100; forest and domain mode 2025; schema 91 |

## Invariant matrix

| Invariant | Primary source | Section | Evidence class | Outcomes | Cases |
| --- | --- | --- | --- | --- | ---: |
| `CKT-LOS-001` | [Hybrid cloud Kerberos trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) (Windows Server 2025 documentation) | Prerequisites and deployment validation | `windows-observation` | `skip` (windows_11_client_missing) | 1 |
| `CKT-PARTIAL-001` | [Windows Hello for Business authentication](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-authentication) (Windows Server 2025 documentation) | Cloud Kerberos trust authentication | `windows-observation` | `skip` (windows_11_client_missing) | 1 |
| `CKT-PRECEDENCE-001` | [Hybrid cloud Kerberos trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) (Windows Server 2025 documentation) | Policy configuration | `windows-observation` | `skip` (cloud_trust_policy_unverified) | 1 |
| `CKT-RODC-001` | [Hybrid cloud Kerberos trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) (Windows Server 2025 documentation) | Azure AD Kerberos and password replication policy | `windows-observation` | `skip` (cloud_kerberos_object_missing) | 1 |
| `DMSA-ACL-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Account migration permissions | `windows-observation` | `observe` (temporary_acl_lifecycle_observed) | 1 |
| `DMSA-EVENT-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Auditing dMSA activity | `windows-observation` | `inconclusive` (supported_events_not_observed) | 1 |
| `DMSA-LINK-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Account migration | `windows-observation` | `observe` (reciprocal_links_observed) | 1 |
| `DMSA-MACHINE-001` | [Set up delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (Windows Server 2025 documentation) | Grant client access to the dMSA | `windows-observation` | `observe` (explicit_enrollment_observed) | 1 |
| `DMSA-ROLLBACK-001` | [Set up delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (Windows Server 2025 documentation) | Reset a dMSA account | `windows-observation` | `observe` (checkpoint_restore_verified) | 1 |
| `DMSA-RWDC-001` | [Set up delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (Windows Server 2025 documentation) | Prerequisites | `windows-observation` | `observe` (rodc_local_transition_observed) | 1 |
| `DMSA-SPN-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Account migration completion | `windows-observation` | `observe` (ordered_state_transfer_observed) | 1 |
| `DMSA-STATE-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Migration states | `windows-observation` | `observe` (bounded_lifecycle_observation) | 1 |
| `OIDC-AUD-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 3.1.3.7 | `spec-oracle` | `not recorded` | 0 |
| `OIDC-ISS-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 3.1.3.7 | `spec-oracle` | `not recorded` | 0 |
| `OIDC-NONCE-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 3.1.2.1 and 3.1.3.7 | `spec-oracle` | `not recorded` | 0 |
| `OIDC-TIME-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 2 and 3.1.3.7 | `spec-oracle` | `not recorded` | 0 |
| `PAC-ATTR-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.14 PAC_ATTRIBUTES_INFO | `local-adapter` | `observe` (attributes_buffer_absent) | 1 |
| `PAC-BOUNDS-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.4 PAC_INFO_BUFFER | `local-adapter` | `not recorded` | 0 |
| `PAC-DLG-001` | [Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (MS-KILE Open Specifications current revision, accessed 2026-10-30) | Domain Local Group Membership processing | `windows-observation` | `observe` (service_ticket_buffers_observed) | 1 |
| `PAC-ORDER-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.8 PAC Signatures | `local-adapter` | `not recorded` | 0 |
| `PAC-REQ-001` | [Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (MS-KILE Open Specifications current revision, accessed 2026-10-30) | TGS request PAC requestor validation | `windows-observation` | `inconclusive` (tgt_requestor_not_assessed) | 1 |
| `PAC-RODC-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.8.1 PAC_SIGNATURE_DATA | `windows-observation` | `observe` (rodc_identifier_observed) | 1 |
| `PAC-SIG-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.8 PAC Signatures | `local-adapter` | `observe` (signature_roles_observed) | 1 |
| `PAC-TGS-001` | [Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (MS-KILE Open Specifications current revision, accessed 2026-10-30) | TGS ticket construction | `windows-observation` | `observe` (service_ticket_issuance_observed) | 1 |
| `STS-ACTOR-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | 0 |
| `STS-LIFETIME-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 and 2.2 | `spec-oracle` | `not recorded` | 0 |
| `STS-REQ-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | 0 |
| `STS-RIGHTS-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | 0 |
| `STS-TARGET-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | 0 |
| `WIF-BIND-001` | [Microsoft Graph federated identity credential overview](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0) (Microsoft Graph REST API v1.0) | federatedIdentityCredential resource | `spec-oracle` | `skip` (tenant_context_missing) | 2 |
| `WIF-FLEX-001` | [Flexible federated identity credentials](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials) (Microsoft Entra workload identities public preview) | Flexible federated identity credential configuration | `spec-oracle` | `not recorded` | 0 |
| `WIF-KEY-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3.1 and 3.2 | `spec-oracle` | `not recorded` | 0 |
| `WIF-MATCH-001` | [Microsoft Graph federated identity credential overview](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0) (Microsoft Graph REST API v1.0) | issuer subject and audiences properties | `spec-oracle` | `not recorded` | 0 |
| `WIF-REPLAY-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3 | `spec-oracle` | `not recorded` | 0 |
| `WIF-TIME-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3.1 and 3.2 | `spec-oracle` | `not recorded` | 0 |
| `WIF-TRANSPORT-001` | [Microsoft identity platform OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow) (Microsoft identity platform v2.0 endpoint) | Protocol diagram and access token request | `spec-oracle` | `not recorded` | 0 |
| `WIF-TYPE-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3 | `spec-oracle` | `not recorded` | 0 |

## Observations

### `ckt-line-of-sight`

- Invariant: `CKT-LOS-001`
- Outcome: `skip`
- Reason: `windows_11_client_missing`
- Evidence class: `windows-observation`

### `ckt-partial-tgt-gate`

- Invariant: `CKT-PARTIAL-001`
- Outcome: `skip`
- Reason: `windows_11_client_missing`
- Evidence class: `windows-observation`

### `ckt-policy-precedence-gate`

- Invariant: `CKT-PRECEDENCE-001`
- Outcome: `skip`
- Reason: `cloud_trust_policy_unverified`
- Evidence class: `windows-observation`

### `ckt-rodc-object-gate`

- Invariant: `CKT-RODC-001`
- Outcome: `skip`
- Reason: `cloud_kerberos_object_missing`
- Evidence class: `windows-observation`

### `dmsa-temporary-acl-lifecycle`

- Invariant: `DMSA-ACL-001`
- Outcome: `observe`
- Reason: `temporary_acl_lifecycle_observed`
- Evidence class: `windows-observation`

### `dmsa-event-directory-correlation`

- Invariant: `DMSA-EVENT-001`
- Outcome: `inconclusive`
- Reason: `supported_events_not_observed`
- Evidence class: `windows-observation`

### `dmsa-reciprocal-migration-links`

- Invariant: `DMSA-LINK-001`
- Outcome: `observe`
- Reason: `reciprocal_links_observed`
- Evidence class: `windows-observation`

### `dmsa-enrolled-machine`

- Invariant: `DMSA-MACHINE-001`
- Outcome: `observe`
- Reason: `explicit_enrollment_observed`
- Evidence class: `windows-observation`

### `dmsa-baseline-restore`

- Invariant: `DMSA-ROLLBACK-001`
- Outcome: `observe`
- Reason: `checkpoint_restore_verified`
- Evidence class: `windows-observation`

### `dmsa-rwdc-rodc-boundary`

- Invariant: `DMSA-RWDC-001`
- Outcome: `observe`
- Reason: `rodc_local_transition_observed`
- Evidence class: `windows-observation`

### `dmsa-ordered-state-transfer`

- Invariant: `DMSA-SPN-001`
- Outcome: `observe`
- Reason: `ordered_state_transfer_observed`
- Evidence class: `windows-observation`

### `dmsa-state-transitions`

- Invariant: `DMSA-STATE-001`
- Outcome: `observe`
- Reason: `bounded_lifecycle_observation`
- Evidence class: `windows-observation`

### `pac-attributes-service-ticket`

- Invariant: `PAC-ATTR-001`
- Outcome: `observe`
- Reason: `attributes_buffer_absent`
- Evidence class: `windows-observation`

### `pac-domain-local-processing`

- Invariant: `PAC-DLG-001`
- Outcome: `observe`
- Reason: `service_ticket_buffers_observed`
- Evidence class: `windows-observation`

### `pac-requestor-tgt-boundary`

- Invariant: `PAC-REQ-001`
- Outcome: `inconclusive`
- Reason: `tgt_requestor_not_assessed`
- Evidence class: `windows-observation`

### `pac-rodc-identifier`

- Invariant: `PAC-RODC-001`
- Outcome: `observe`
- Reason: `rodc_identifier_observed`
- Evidence class: `windows-observation`

### `pac-signature-roles`

- Invariant: `PAC-SIG-001`
- Outcome: `observe`
- Reason: `signature_roles_observed`
- Evidence class: `windows-observation`

### `pac-service-ticket-issuance`

- Invariant: `PAC-TGS-001`
- Outcome: `observe`
- Reason: `service_ticket_issuance_observed`
- Evidence class: `windows-observation`

### `wif-live-gate-ubuntu-lab`

- Invariant: `WIF-BIND-001`
- Outcome: `skip`
- Reason: `tenant_context_missing`
- Evidence class: `entra-observation`

### `wif-live-gate-windows-lab`

- Invariant: `WIF-BIND-001`
- Outcome: `skip`
- Reason: `tenant_context_missing`
- Evidence class: `entra-observation`

## Limitations

- Local oracle results are not statements about hosted service behavior.
- Live Entra and Cloud Kerberos behavior remains unassessed when its prerequisite gate reports `skip`.
- PAC requestor binding remains inconclusive where only the service ticket, not the encrypted TGT, was decoded.
- CWE and CVSS remain `not assessed` until product behavior and impact are independently confirmed.

## Artifact hashes

- `record/ckt-line-of-sight/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-partial-tgt-gate/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-policy-precedence-gate/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-rodc-object-gate/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/dmsa-baseline-restore/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-enrolled-machine/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-event-directory-correlation/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-ordered-state-transfer/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-reciprocal-migration-links/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-rwdc-rodc-boundary/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-state-transitions/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-temporary-acl-lifecycle/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/pac-attributes-service-ticket/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-domain-local-processing/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-requestor-tgt-boundary/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-rodc-identifier/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-service-ticket-issuance/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-signature-roles/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/wif-live-gate-ubuntu-lab/source-ledger`: `9a6f96a6de428e34d2c1cd136fb3ebb631a82a33d7c3152748ca0ab028956b10`
- `record/wif-live-gate-windows-lab/source-ledger`: `683102d242f601909ae64bbff71c96ff09970e41fd842de5503e2182ee9215f7`
- `source-manifest/task7-windows-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `source-manifest/task8-pac-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `source-manifest/task9-cloud-gate`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `source-manifest/task9-ubuntu-ledger`: `9a6f96a6de428e34d2c1cd136fb3ebb631a82a33d7c3152748ca0ab028956b10`
- `source-manifest/task9-windows-ledger`: `683102d242f601909ae64bbff71c96ff09970e41fd842de5503e2182ee9215f7`
