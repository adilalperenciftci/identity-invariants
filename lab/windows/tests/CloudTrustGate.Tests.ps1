$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $labRoot 'Test-CloudTrustGate.ps1')

Describe 'Cloud Kerberos trust preflight gate' {
    It 'defines a read-only prerequisite plan' {
        $plan = Get-CloudTrustGatePlan

        $plan.ReadOnly | Should Be $true
        $plan.Windows11Client | Should Be 'ID-CL01'
        ($plan.RequiredChecks -join ',') | Should Be (
            'server-2025-rwdc,azureadkerberos-object,password-replication-policy,' +
            'cloud-trust-policy,windows-11-client,line-of-sight,partial-tgt'
        )
    }

    It 'requires the exact password replication policy groups' {
        $incomplete = [pscustomobject]@{
            'msDS-RevealOnDemandGroup' = @()
            'msDS-NeverRevealGroup' = @('CN=Denied,DC=idlab,DC=test')
        }
        $arbitrary = [pscustomobject]@{
            'msDS-RevealOnDemandGroup' = @('CN=Allowed,DC=idlab,DC=test')
            'msDS-NeverRevealGroup' = @('CN=Denied,DC=idlab,DC=test')
        }
        $complete = [pscustomobject]@{
            'msDS-RevealOnDemandGroup' = @(
                'CN=Allowed RODC Password Replication Group,CN=Users,DC=idlab,DC=test'
            )
            'msDS-NeverRevealGroup' = @(
                'CN=Denied RODC Password Replication Group,CN=Users,DC=idlab,DC=test'
            )
        }

        (Test-CloudTrustPasswordReplicationPolicy -DirectoryObject $incomplete) |
            Should Be $false
        (Test-CloudTrustPasswordReplicationPolicy -DirectoryObject $arbitrary) |
            Should Be $false
        (Test-CloudTrustPasswordReplicationPolicy -DirectoryObject $complete) |
            Should Be $true
    }

    It 'fails closed when directory prerequisites cannot be read' {
        Mock Import-Module { throw 'module unavailable' } -ParameterFilter {
            $Name -eq 'ActiveDirectory'
        }

        $inventory = Get-CloudTrustInventory
        $result = Test-CloudTrustInventory -Inventory $inventory

        $result.Outcome | Should Be 'skip'
        $result.NetworkRequestCount | Should Be 0
        ($result.ReasonCodes -contains 'server_2025_rwdc_missing') |
            Should Be $true
    }

    It 'skips deterministically when cloud objects and client are absent' {
        $result = Test-CloudTrustInventory -Inventory ([ordered]@{
            Server2025Rwdc = $true
            AzureAdKerberosObject = $false
            PasswordReplicationPolicyIntact = $false
            CloudTrustPolicySelected = $false
            CertificateTrustPolicySelected = $false
            Windows11Client = $false
            ClientJoined = $false
            LineOfSight = $true
            PartialTgt = $false
        })

        $result.Outcome | Should Be 'skip'
        ($result.ReasonCodes -join ',') | Should Be (
            'cloud_kerberos_object_missing,password_replication_policy_unverified,' +
            'cloud_trust_policy_unverified,windows_11_client_missing,' +
            'partial_tgt_missing'
        )
        $result.NetworkRequestCount | Should Be 0
    }

    It 'records certificate-trust precedence instead of classifying cloud trust' {
        $result = Test-CloudTrustInventory -Inventory ([ordered]@{
            Server2025Rwdc = $true
            AzureAdKerberosObject = $true
            PasswordReplicationPolicyIntact = $true
            CloudTrustPolicySelected = $true
            CertificateTrustPolicySelected = $true
            Windows11Client = $true
            ClientJoined = $true
            LineOfSight = $true
            PartialTgt = $true
        })

        $result.Outcome | Should Be 'skip'
        ($result.ReasonCodes -contains 'certificate_trust_precedence') | Should Be $true
    }

    It 'does not infer client join state from a directory object' {
        $result = Test-CloudTrustInventory -Inventory ([ordered]@{
            Server2025Rwdc = $true
            AzureAdKerberosObject = $true
            PasswordReplicationPolicyIntact = $true
            CloudTrustPolicySelected = $true
            CertificateTrustPolicySelected = $false
            Windows11Client = $true
            ClientJoined = $false
            LineOfSight = $true
            PartialTgt = $true
        })

        $result.Outcome | Should Be 'skip'
        ($result.ReasonCodes -contains 'windows_11_client_missing') | Should Be $true
    }

    It 'does not inherit RWDC line of sight outside the expected client' {
        Mock Import-Module {}
        Mock Get-ADDomainController {
            [pscustomobject]@{
                ComputerObjectDN = 'CN=ID-DC01,DC=idlab,DC=test'
                IsReadOnly = $false
            }
        }
        Mock Get-ADComputer {
            param($Identity)

            if (-not [string]::IsNullOrEmpty($Identity)) {
                return [pscustomobject]@{
                    OperatingSystem = 'Windows Server 2025 Standard'
                }
            }
            return $null
        }
        Mock Get-ADDomain {
            [pscustomobject]@{ DNSRoot = 'idlab.test' }
        }

        $inventory = Get-CloudTrustInventory

        $env:COMPUTERNAME | Should Not Be 'ID-CL01'
        $inventory.Windows11Client | Should Be $false
        $inventory.ClientJoined | Should Be $false
        $inventory.LineOfSight | Should Be $false
        Assert-MockCalled Get-ADDomain -Times 0
    }

    It 'passes only a complete cloud-trust inventory' {
        $result = Test-CloudTrustInventory -Inventory ([ordered]@{
            Server2025Rwdc = $true
            AzureAdKerberosObject = $true
            PasswordReplicationPolicyIntact = $true
            CloudTrustPolicySelected = $true
            CertificateTrustPolicySelected = $false
            Windows11Client = $true
            ClientJoined = $true
            LineOfSight = $true
            PartialTgt = $true
        })

        $result.Outcome | Should Be 'pass'
        $result.ReasonCodes.Count | Should Be 0
        $result.NetworkRequestCount | Should Be 0
    }
}
