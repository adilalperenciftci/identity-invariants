$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $labRoot 'Initialize-IdentityForest.ps1')
. (Join-Path $labRoot 'Configure-IdentityMember.ps1')

Describe 'Identity forest contract' {
    BeforeEach {
        Mock Get-NetAdapter {
            [pscustomobject]@{
                Status = 'Up'
                InterfaceDescription = 'Microsoft Hyper-V Network Adapter'
                ifIndex = 7
            }
        }
    }

    It 'defines the exact isolated Server 2025 forest' {
        $plan = Get-IdentityForestPlan

        $plan.DomainName | Should Be 'idlab.test'
        $plan.DomainNetbiosName | Should Be 'IDLAB'
        $plan.ForestMode | Should Be 'Win2025'
        $plan.DomainMode | Should Be 'Win2025'
        $plan.KdsRootKeyRequired | Should Be $true
        $plan.KerberosOperationalLog | Should Be (
            'Microsoft-Windows-Kerberos/Operational'
        )
        ($plan.KerberosEncryptionTypes -join ',') | Should Be 'AES128,AES256'
        ($plan.Nodes.Name -join ',') | Should Be 'ID-DC01,ID-RODC01,ID-SRV01'
        ($plan.Nodes.Role -join ',') | Should Be 'RWDC,RODC,Member'
    }

    It 'requires the documented dMSA schema attributes' {
        $plan = Get-IdentityForestPlan

        ($plan.SchemaAttributes -contains 'msDS-DelegatedMSAState') | Should Be $true
        (
            $plan.SchemaAttributes -contains 'msDS-ManagedAccountPrecededByLink'
        ) | Should Be $true
        (
            $plan.SchemaAttributes -contains 'msDS-ManagedAccountPrecededByLinkBL'
        ) | Should Be $true
        (
            $plan.SchemaAttributes -contains 'msDS-SupersededManagedAccountLink'
        ) | Should Be $true
        (
            $plan.SchemaAttributes -contains 'msDS-SupersededServiceAccountState'
        ) | Should Be $true
    }

    It 'accepts only the expected static address without a default route' {
        Mock Get-NetIPAddress {
            [pscustomobject]@{
                IPAddress = '172.28.30.10'
                PrefixLength = 24
                InterfaceIndex = 7
            }
        }
        Mock Get-NetRoute { $null }

        $result = Assert-IdentityPrivateNetwork `
            -ExpectedIpAddress '172.28.30.10'

        $result.DefaultRoutes | Should Be 0
        $result.IpAddress | Should Be '172.28.30.10'
    }

    It 'rejects the lab address when it is bound to a non-Hyper-V adapter' {
        Mock Get-NetIPAddress {
            [pscustomobject]@{
                IPAddress = '172.28.30.10'
                PrefixLength = 24
                InterfaceIndex = 5
            }
        }
        Mock Get-NetRoute { $null }

        $message = $null
        try {
            Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.10'
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }
        $message | Should Match 'static identity-lab address is absent'
    }

    It 'rejects a default route before any forest mutation' {
        Mock Get-NetIPAddress {
            [pscustomobject]@{
                IPAddress = '172.28.30.10'
                PrefixLength = 24
                InterfaceIndex = 7
            }
        }
        Mock Get-NetRoute {
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0' }
        }

        $message = $null
        try {
            Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.10'
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }
        $message | Should Match 'default route'
    }

    It 'permits an isolated link-local capture adapter' {
        Mock Get-NetIPAddress {
            [pscustomobject]@{
                IPAddress = '172.28.30.10'
                PrefixLength = 24
                InterfaceIndex = 7
            }
            [pscustomobject]@{
                IPAddress = '169.254.10.20'
                PrefixLength = 16
                InterfaceIndex = 5
            }
        }
        Mock Get-NetRoute { $null }

        $result = Assert-IdentityPrivateNetwork `
            -ExpectedIpAddress '172.28.30.10'

        $result.DefaultRoutes | Should Be 0
    }

    It 'rejects a second routable IPv4 address' {
        Mock Get-NetIPAddress {
            [pscustomobject]@{
                IPAddress = '172.28.30.10'
                PrefixLength = 24
                InterfaceIndex = 7
            }
            [pscustomobject]@{
                IPAddress = '192.0.2.10'
                PrefixLength = 24
                InterfaceIndex = 5
            }
        }
        Mock Get-NetRoute { $null }

        $message = $null
        try {
            Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.10'
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }
        $message | Should Match 'Unexpected IPv4 address'
    }

    It 'registers only the identity interface in DNS' {
        Mock Get-NetIPAddress {
            [pscustomobject]@{
                IPAddress = '172.28.30.10'
                PrefixLength = 24
                InterfaceIndex = 7
            }
        }
        Mock Get-DnsClient {
            [pscustomobject]@{
                InterfaceIndex = 5
                RegisterThisConnectionsAddress = $true
            }
            [pscustomobject]@{
                InterfaceIndex = 7
                RegisterThisConnectionsAddress = $true
            }
        }
        Mock Set-DnsClient {
            param($InterfaceIndex, $RegisterThisConnectionsAddress, $ErrorAction)
        }

        $result = Set-IdentityDnsRegistration `
            -ExpectedIpAddress '172.28.30.10' `
            -Confirm:$false

        $result.IdentityInterfaceIndex | Should Be 7
        $result.Changes | Should Be 1
        Assert-MockCalled Set-DnsClient -Times 1 -ParameterFilter {
            $InterfaceIndex -eq 5 -and
            $RegisterThisConnectionsAddress -eq $false
        }
    }
}
