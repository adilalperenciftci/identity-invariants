# Microsoft Identity Protocol Invariant Evidence

## Assessment status

- CWE: `not assessed`
- CVSS: `not assessed`

## Evidence manifest

- Ledger: `evidence.jsonl`
- Ledger SHA-256: `f2a51ed468ce95690cb8276ba766f1369e08db5c12401b78b5a634c6a41d93f2`
- Record count: `25`

## Environment fingerprint

| Component | Fingerprint |
| --- | --- |
| seed | 20261030 |
| topology | ID-DC01, ID-RODC01, and ID-SRV01 on private Bluex-Identity; no default route |
| ubuntu | Ubuntu 24.04.5 LTS; Python 3.12.3 |
| windows | Windows Server 2025 build 26100; forest and domain mode 2025; schema 91 |

## Invariant matrix

| Invariant | Primary source | Section | Catalog class | Observed class | Outcomes | Cases |
| --- | --- | --- | --- | --- | --- | ---: |
| `CKT-LOS-001` | [Hybrid cloud Kerberos trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) (Windows Server 2025 documentation) | Prerequisites and deployment validation | `windows-observation` | `windows-observation` | `windows-observation`: `skip` (windows_11_client_missing) | 1 |
| `CKT-PARTIAL-001` | [Windows Hello for Business authentication](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-authentication) (Windows Server 2025 documentation) | Cloud Kerberos trust authentication | `windows-observation` | `windows-observation` | `windows-observation`: `skip` (windows_11_client_missing) | 1 |
| `CKT-PRECEDENCE-001` | [Hybrid cloud Kerberos trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) (Windows Server 2025 documentation) | Policy configuration | `windows-observation` | `windows-observation` | `windows-observation`: `skip` (cloud_trust_policy_unverified) | 1 |
| `CKT-RODC-001` | [Hybrid cloud Kerberos trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) (Windows Server 2025 documentation) | Azure AD Kerberos and password replication policy | `windows-observation` | `windows-observation` | `windows-observation`: `skip` (cloud_kerberos_object_missing) | 1 |
| `DMSA-ACL-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Account migration permissions | `windows-observation` | `windows-observation` | `windows-observation`: `accept` (ordered_completion) | 1 |
| `DMSA-EVENT-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Auditing dMSA activity | `windows-observation` | `windows-observation` | `windows-observation`: `inconclusive` (supported_events_not_observed) | 1 |
| `DMSA-LINK-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Account migration | `windows-observation` | `windows-observation` | `windows-observation`: `observe` (reciprocal_links_replicated) | 1 |
| `DMSA-MACHINE-001` | [Set up delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (Windows Server 2025 documentation) | Grant client access to the dMSA | `windows-observation` | `windows-observation` | `windows-observation`: `observe` (allow_list_membership_is_explicit) | 1 |
| `DMSA-ROLLBACK-001` | [Set up delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (Windows Server 2025 documentation) | Reset a dMSA account | `windows-observation` | `windows-observation` | `windows-observation`: `accept` (checkpoint_restore_digest_match)<br>`windows-observation`: `observe` (state_links_restored_enrollment_cleared) | 3 |
| `DMSA-RWDC-001` | [Set up delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (Windows Server 2025 documentation) | Prerequisites | `windows-observation` | `windows-observation` | `windows-observation`: `accept` (writable_directory_transition)<br>`windows-observation`: `observe` (rodc_local_transition_persisted) | 2 |
| `DMSA-SPN-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Account migration completion | `windows-observation` | `windows-observation` | `windows-observation`: `accept` (ordered_completion) | 1 |
| `DMSA-STATE-001` | [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) (Windows Server 2025 documentation) | Migration states | `windows-observation` | `windows-observation` | `windows-observation`: `accept` (ordered_completion)<br>`windows-observation`: `inconclusive` (documented_state_three_not_observed)<br>`windows-observation`: `reject` (invalid_transition) | 3 |
| `OIDC-AUD-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 3.1.3.7 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `OIDC-ISS-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 3.1.3.7 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `OIDC-NONCE-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 3.1.2.1 and 3.1.3.7 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `OIDC-TIME-001` | [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) (OpenID Connect Core 1.0, errata set 2) | 2 and 3.1.3.7 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `PAC-ATTR-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.14 PAC_ATTRIBUTES_INFO | `local-adapter` | `windows-observation` | `windows-observation`: `observe` (attributes_buffer_absent) | 1 |
| `PAC-BOUNDS-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.4 PAC_INFO_BUFFER | `local-adapter` | `not recorded` | `not recorded` | 0 |
| `PAC-DLG-001` | [Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (MS-KILE Open Specifications current revision, accessed 2026-10-30) | Domain Local Group Membership processing | `windows-observation` | `windows-observation` | `windows-observation`: `observe` (service_ticket_buffers_observed) | 1 |
| `PAC-ORDER-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.8 PAC Signatures | `local-adapter` | `not recorded` | `not recorded` | 0 |
| `PAC-REQ-001` | [Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (MS-KILE Open Specifications current revision, accessed 2026-10-30) | TGS request PAC requestor validation | `windows-observation` | `windows-observation` | `windows-observation`: `inconclusive` (tgt_requestor_not_assessed) | 1 |
| `PAC-RODC-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.8.1 PAC_SIGNATURE_DATA | `windows-observation` | `windows-observation` | `windows-observation`: `observe` (rodc_identifier_observed) | 1 |
| `PAC-SIG-001` | [Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (MS-PAC Open Specifications current revision, accessed 2026-10-30) | 2.8 PAC Signatures | `local-adapter` | `windows-observation` | `windows-observation`: `observe` (signature_roles_observed) | 1 |
| `PAC-TGS-001` | [Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (MS-KILE Open Specifications current revision, accessed 2026-10-30) | TGS ticket construction | `windows-observation` | `windows-observation` | `windows-observation`: `observe` (service_ticket_issuance_observed) | 1 |
| `STS-ACTOR-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `STS-LIFETIME-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 and 2.2 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `STS-REQ-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `STS-RIGHTS-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `STS-TARGET-001` | [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (RFC 8693, January 2020) | 2.1 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-BIND-001` | [Microsoft Graph federated identity credential overview](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0) (Microsoft Graph REST API v1.0) | federatedIdentityCredential resource | `spec-oracle` | `entra-observation` | `entra-observation`: `skip` (tenant_context_missing) | 2 |
| `WIF-FLEX-001` | [Flexible federated identity credentials](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials) (Microsoft Entra workload identities public preview) | Flexible federated identity credential configuration | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-KEY-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3.1 and 3.2 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-MATCH-001` | [Microsoft Graph federated identity credential overview](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0) (Microsoft Graph REST API v1.0) | issuer subject and audiences properties | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-REPLAY-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-TIME-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3.1 and 3.2 | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-TRANSPORT-001` | [Microsoft identity platform OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow) (Microsoft identity platform v2.0 endpoint) | Protocol diagram and access token request | `spec-oracle` | `not recorded` | `not recorded` | 0 |
| `WIF-TYPE-001` | [JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523) (RFC 7523, May 2015) | 3 | `spec-oracle` | `not recorded` | `not recorded` | 0 |

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

### `dmsa-started-to-complete--dmsa-acl-001`

- Invariant: `DMSA-ACL-001`
- Outcome: `accept`
- Reason: `ordered_completion`
- Evidence class: `windows-observation`

### `dmsa-event-directory-correlation`

- Invariant: `DMSA-EVENT-001`
- Outcome: `inconclusive`
- Reason: `supported_events_not_observed`
- Evidence class: `windows-observation`

### `dmsa-reciprocal-migration-links`

- Invariant: `DMSA-LINK-001`
- Outcome: `observe`
- Reason: `reciprocal_links_replicated`
- Evidence class: `windows-observation`

### `dmsa-enrolled-machine`

- Invariant: `DMSA-MACHINE-001`
- Outcome: `observe`
- Reason: `allow_list_membership_is_explicit`
- Evidence class: `windows-observation`

### `dmsa-baseline-restore`

- Invariant: `DMSA-ROLLBACK-001`
- Outcome: `accept`
- Reason: `checkpoint_restore_digest_match`
- Evidence class: `windows-observation`

### `dmsa-reset-to-documented-state`

- Invariant: `DMSA-ROLLBACK-001`
- Outcome: `observe`
- Reason: `state_links_restored_enrollment_cleared`
- Evidence class: `windows-observation`

### `dmsa-undo-to-documented-state`

- Invariant: `DMSA-ROLLBACK-001`
- Outcome: `observe`
- Reason: `state_links_restored_enrollment_cleared`
- Evidence class: `windows-observation`

### `dmsa-rodc-migration-write`

- Invariant: `DMSA-RWDC-001`
- Outcome: `observe`
- Reason: `rodc_local_transition_persisted`
- Evidence class: `windows-observation`

### `dmsa-rwdc-migration-write`

- Invariant: `DMSA-RWDC-001`
- Outcome: `accept`
- Reason: `writable_directory_transition`
- Evidence class: `windows-observation`

### `dmsa-started-to-complete--dmsa-spn-001`

- Invariant: `DMSA-SPN-001`
- Outcome: `accept`
- Reason: `ordered_completion`
- Evidence class: `windows-observation`

### `dmsa-complete-before-start`

- Invariant: `DMSA-STATE-001`
- Outcome: `reject`
- Reason: `invalid_transition`
- Evidence class: `windows-observation`

### `dmsa-standalone`

- Invariant: `DMSA-STATE-001`
- Outcome: `inconclusive`
- Reason: `documented_state_three_not_observed`
- Evidence class: `windows-observation`

### `dmsa-started-to-complete--dmsa-state-001`

- Invariant: `DMSA-STATE-001`
- Outcome: `accept`
- Reason: `ordered_completion`
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
- dMSA standalone state 3 was not observed on build 26100 and remains inconclusive.
- dMSA Reset and Undo restored state and links but cleared machine enrollment; exact cleanup required checkpoint restoration.
- CWE and CVSS remain `not assessed` until product behavior and impact are independently confirmed.

## Artifact hashes

- `record/ckt-line-of-sight/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-line-of-sight/source-record`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-partial-tgt-gate/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-partial-tgt-gate/source-record`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-policy-precedence-gate/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-policy-precedence-gate/source-record`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-rodc-object-gate/source-ledger`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/ckt-rodc-object-gate/source-record`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `record/dmsa-baseline-restore/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-baseline-restore/source-record`: `10a41931157ea15bdae43f981795da94327ff117a128a05796e0942f903d5bf7`
- `record/dmsa-complete-before-start/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-complete-before-start/source-record`: `afc7a6ccaaf23641982253a217521961bf4a0366b21dac9a1490fdcd48e53ed2`
- `record/dmsa-enrolled-machine/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-enrolled-machine/source-record`: `3beadb0c4ead768999593cf42d6db1013d35dd24fa548600de6ee8e5cbafcb12`
- `record/dmsa-event-directory-correlation/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-event-directory-correlation/source-record`: `5cd381882d94c9624fafb244712a2bb97c0e4f4cef442821fb7291709041d82b`
- `record/dmsa-reciprocal-migration-links/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-reciprocal-migration-links/source-record`: `5f3320bf5180927b7288ca6a515b9a30a3fdf84e508af2cc1e06a64058feb8e4`
- `record/dmsa-reset-to-documented-state/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-reset-to-documented-state/source-record`: `89d931cf3e9dc280d5fe2a9fe5812ac3a2cf764a6c84fadeef7fcd640ec7132e`
- `record/dmsa-rodc-migration-write/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-rodc-migration-write/source-record`: `4d014c3c70adaecd568f5d602f8acc03e2530d92412ba0ef48f86dfa3b67b929`
- `record/dmsa-rwdc-migration-write/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-rwdc-migration-write/source-record`: `05ef5fb49d9003cde66457177b58dbbfa3271aed25864af982b3c0a7785cf135`
- `record/dmsa-standalone/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-standalone/source-record`: `34800b16b0f8e89b88bbf9b6a725f354f65c3eaf22e8bad9d8b8b8bcb73747c2`
- `record/dmsa-started-to-complete--dmsa-acl-001/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-started-to-complete--dmsa-acl-001/source-record`: `cf6e0bcb4faa2c6d3c886c5c9d15784043dd09035716980f4c7a5ad6c756417b`
- `record/dmsa-started-to-complete--dmsa-spn-001/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-started-to-complete--dmsa-spn-001/source-record`: `cf6e0bcb4faa2c6d3c886c5c9d15784043dd09035716980f4c7a5ad6c756417b`
- `record/dmsa-started-to-complete--dmsa-state-001/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-started-to-complete--dmsa-state-001/source-record`: `cf6e0bcb4faa2c6d3c886c5c9d15784043dd09035716980f4c7a5ad6c756417b`
- `record/dmsa-undo-to-documented-state/source-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `record/dmsa-undo-to-documented-state/source-record`: `d13a70bf1b23b13fae3b2c1cf4b4482914406507cedce3945b09f8eb07ce1109`
- `record/pac-attributes-service-ticket/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-attributes-service-ticket/source-record-rodc`: `d77d0ed8da9a12196794998e8c69ff19aba3012c80cc86c1b132d30314e534be`
- `record/pac-attributes-service-ticket/source-record-rwdc`: `44f5e1a4644724f46b53971da784a2531a36453127015b539d4186bfd29e4e06`
- `record/pac-domain-local-processing/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-domain-local-processing/source-record-rodc`: `d77d0ed8da9a12196794998e8c69ff19aba3012c80cc86c1b132d30314e534be`
- `record/pac-domain-local-processing/source-record-rwdc`: `44f5e1a4644724f46b53971da784a2531a36453127015b539d4186bfd29e4e06`
- `record/pac-requestor-tgt-boundary/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-requestor-tgt-boundary/source-record-rodc`: `d77d0ed8da9a12196794998e8c69ff19aba3012c80cc86c1b132d30314e534be`
- `record/pac-requestor-tgt-boundary/source-record-rwdc`: `44f5e1a4644724f46b53971da784a2531a36453127015b539d4186bfd29e4e06`
- `record/pac-rodc-identifier/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-rodc-identifier/source-record-rodc`: `d77d0ed8da9a12196794998e8c69ff19aba3012c80cc86c1b132d30314e534be`
- `record/pac-rodc-identifier/source-record-rwdc`: `44f5e1a4644724f46b53971da784a2531a36453127015b539d4186bfd29e4e06`
- `record/pac-service-ticket-issuance/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-service-ticket-issuance/source-record-rodc`: `d77d0ed8da9a12196794998e8c69ff19aba3012c80cc86c1b132d30314e534be`
- `record/pac-service-ticket-issuance/source-record-rwdc`: `44f5e1a4644724f46b53971da784a2531a36453127015b539d4186bfd29e4e06`
- `record/pac-signature-roles/source-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `record/pac-signature-roles/source-record-rodc`: `d77d0ed8da9a12196794998e8c69ff19aba3012c80cc86c1b132d30314e534be`
- `record/pac-signature-roles/source-record-rwdc`: `44f5e1a4644724f46b53971da784a2531a36453127015b539d4186bfd29e4e06`
- `record/wif-live-gate-ubuntu-lab/source-ledger`: `9a6f96a6de428e34d2c1cd136fb3ebb631a82a33d7c3152748ca0ab028956b10`
- `record/wif-live-gate-ubuntu-lab/source-record`: `5dbdab7652f42a2dcc3e9e4111ed2305b34361e9a585ab31c3994fb69b1c1395`
- `record/wif-live-gate-windows-lab/source-ledger`: `683102d242f601909ae64bbff71c96ff09970e41fd842de5503e2182ee9215f7`
- `record/wif-live-gate-windows-lab/source-record`: `31c45ebd581a1056cf3f3eb07e68591c71174b693c560efbb8c14e6c78ed8616`
- `source-manifest/task7-windows-ledger`: `024bbf6c01333a08a383587cf701985d26dbe9eef975518aebc271e8f25ef9fc`
- `source-manifest/task8-pac-ledger`: `3d1bda6af895f7de22eeaa5f6df5707c60d9ee6a631b507c226a309845707ffe`
- `source-manifest/task9-cloud-gate`: `95c75bd14adcac7b9fb22c0e4abde06fdeb33afe1d8cc43be47e4d0d32ddf271`
- `source-manifest/task9-ubuntu-ledger`: `9a6f96a6de428e34d2c1cd136fb3ebb631a82a33d7c3152748ca0ab028956b10`
- `source-manifest/task9-windows-ledger`: `683102d242f601909ae64bbff71c96ff09970e41fd842de5503e2182ee9215f7`
