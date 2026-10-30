Set-StrictMode -Version Latest

function Get-IdentityForestPlan {
    [CmdletBinding()]
    param()

    [pscustomobject][ordered]@{
        FormatVersion = 1
        DomainName = 'idlab.test'
        DomainNetbiosName = 'IDLAB'
        ForestMode = 'Win2025'
        DomainMode = 'Win2025'
        KdsRootKeyRequired = $true
        KerberosOperationalLog = 'Microsoft-Windows-Kerberos/Operational'
        KerberosEncryptionTypes = @('AES128', 'AES256')
        SchemaAttributes = @(
            'msDS-DelegatedMSAState',
            'msDS-ManagedAccountPrecededByLink',
            'msDS-ManagedAccountPrecededByLinkBL',
            'msDS-SupersededManagedAccountLink',
            'msDS-SupersededManagedAccountLinkBL',
            'msDS-SupersededServiceAccountState'
        )
        Nodes = @(
            [pscustomobject][ordered]@{
                Name = 'ID-DC01'
                IpAddress = '172.28.30.10'
                Role = 'RWDC'
            },
            [pscustomobject][ordered]@{
                Name = 'ID-RODC01'
                IpAddress = '172.28.30.11'
                Role = 'RODC'
            },
            [pscustomobject][ordered]@{
                Name = 'ID-SRV01'
                IpAddress = '172.28.30.20'
                Role = 'Member'
            }
        )
    }
}

function Assert-IdentityPrivateNetwork {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('172.28.30.10', '172.28.30.11', '172.28.30.20')]
        [string]$ExpectedIpAddress
    )

    $addresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notmatch '^127\.' }
    )
    $identityAdapters = @(
        Get-NetAdapter -ErrorAction Stop |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.InterfaceDescription -eq 'Microsoft Hyper-V Network Adapter'
        }
    )
    if ($identityAdapters.Count -ne 1) {
        throw 'Exactly one active Hyper-V identity adapter is required.'
    }
    $expected = @(
        $addresses |
        Where-Object {
            $_.IPAddress -eq $ExpectedIpAddress -and
            $_.InterfaceIndex -eq $identityAdapters[0].ifIndex
        }
    )
    if ($expected.Count -ne 1 -or $expected[0].PrefixLength -ne 24) {
        throw "Expected static identity-lab address is absent: $ExpectedIpAddress/24"
    }
    $unexpected = @(
        $addresses |
        Where-Object {
            $_.IPAddress -ne $ExpectedIpAddress -and
            $_.IPAddress -notmatch '^169\.254\.'
        }
    )
    if ($unexpected.Count -ne 0) {
        throw 'Unexpected IPv4 address exists on the identity-lab node.'
    }
    $routes = @(
        Get-NetRoute `
            -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' `
            -ErrorAction SilentlyContinue |
        Where-Object { $null -ne $_ }
    )
    if ($routes.Count -ne 0) {
        throw 'Identity-lab node has a default route.'
    }
    [pscustomobject]@{
        IpAddress = $expected[0].IPAddress
        PrefixLength = $expected[0].PrefixLength
        InterfaceIndex = $identityAdapters[0].ifIndex
        DefaultRoutes = $routes.Count
    }
}

function Set-IdentityDnsRegistration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('172.28.30.10', '172.28.30.11', '172.28.30.20')]
        [string]$ExpectedIpAddress
    )

    $adapter = Get-NetAdapter -ErrorAction Stop |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.InterfaceDescription -eq 'Microsoft Hyper-V Network Adapter'
        } |
        Select-Object -First 1
    if (-not $adapter) {
        throw 'Active Hyper-V identity adapter is absent.'
    }
    $address = Get-NetIPAddress `
        -AddressFamily IPv4 `
        -IPAddress $ExpectedIpAddress `
        -InterfaceIndex $adapter.ifIndex `
        -ErrorAction Stop
    $targetIndex = $adapter.ifIndex
    $changes = 0
    foreach ($client in @(Get-DnsClient)) {
        $shouldRegister = $client.InterfaceIndex -eq $targetIndex
        if ($client.RegisterThisConnectionsAddress -ne $shouldRegister) {
            if ($PSCmdlet.ShouldProcess(
                "interface $($client.InterfaceIndex)",
                "Set DNS registration to $shouldRegister"
            )) {
                Set-DnsClient `
                    -InterfaceIndex $client.InterfaceIndex `
                    -RegisterThisConnectionsAddress $shouldRegister `
                    -ErrorAction Stop
                $changes++
            }
        }
    }
    [pscustomobject]@{
        IdentityInterfaceIndex = $targetIndex
        Changes = $changes
    }
}

function Install-IdentityRootForest {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][Security.SecureString]$SafeModeAdministratorPassword,
        [Parameter(Mandatory)][Security.SecureString]$ForestAdministratorPassword
    )

    if ($env:COMPUTERNAME -ne 'ID-DC01') {
        throw 'Root forest installation is restricted to ID-DC01.'
    }
    $network = Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.10'
    Set-IdentityDnsRegistration `
        -ExpectedIpAddress '172.28.30.10' `
        -Confirm:$false | Out-Null
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.PartOfDomain) {
        if ($computer.Domain -ne 'idlab.test') {
            throw "ID-DC01 belongs to an unexpected domain: $($computer.Domain)"
        }
        return [pscustomobject]@{
            Changed = $false
            RestartRequired = $false
            DomainName = $computer.Domain
            Network = $network
        }
    }
    if (-not $PSCmdlet.ShouldProcess('ID-DC01', 'Install idlab.test root forest')) {
        return [pscustomobject]@{ Changed = $false; RestartRequired = $false }
    }

    Set-LocalUser `
        -Name 'Administrator' `
        -Password $ForestAdministratorPassword `
        -PasswordNeverExpires:$true `
        -ErrorAction Stop
    Enable-LocalUser -Name 'Administrator' -ErrorAction Stop

    $feature = Install-WindowsFeature `
        -Name AD-Domain-Services, DNS, RSAT-AD-PowerShell `
        -IncludeManagementTools `
        -ErrorAction Stop
    if (-not $feature.Success) {
        throw 'AD DS feature installation did not succeed.'
    }
    Import-Module ADDSDeployment -ErrorAction Stop
    $plan = Get-IdentityForestPlan
    Install-ADDSForest `
        -DomainName $plan.DomainName `
        -DomainNetbiosName $plan.DomainNetbiosName `
        -ForestMode $plan.ForestMode `
        -DomainMode $plan.DomainMode `
        -InstallDns `
        -CreateDnsDelegation:$false `
        -SafeModeAdministratorPassword $SafeModeAdministratorPassword `
        -NoRebootOnCompletion:$true `
        -Force:$true `
        -ErrorAction Stop
    [pscustomobject]@{
        Changed = $true
        RestartRequired = $true
        DomainName = $plan.DomainName
        Network = $network
    }
}

function Initialize-IdentityForestServices {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    if ($env:COMPUTERNAME -ne 'ID-DC01') {
        throw 'Forest services initialization is restricted to ID-DC01.'
    }
    Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.10' | Out-Null
    Set-IdentityDnsRegistration `
        -ExpectedIpAddress '172.28.30.10' `
        -Confirm:$false | Out-Null
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module Kds -ErrorAction Stop
    $rootDse = Get-ADRootDSE `
        -Server 'ID-DC01.idlab.test' `
        -ErrorAction Stop
    if ($rootDse.defaultNamingContext -ne 'DC=idlab,DC=test') {
        throw 'Unexpected default naming context.'
    }

    $createdKdsRootKey = $false
    if (-not (Get-KdsRootKey -ErrorAction Stop)) {
        if ($PSCmdlet.ShouldProcess('idlab.test', 'Create lab KDS root key')) {
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop | Out-Null
            $createdKdsRootKey = $true
        }
    }
    $schemaContext = $rootDse.schemaNamingContext
    $attributes = @{}
    foreach ($name in (Get-IdentityForestPlan).SchemaAttributes) {
        $escaped = $name.Replace("'", "''")
        $match = Get-ADObject `
            -Server 'ID-DC01.idlab.test' `
            -SearchBase $schemaContext `
            -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$escaped))" `
            -Properties lDAPDisplayName, linkID, attributeSyntax, oMSyntax `
            -ErrorAction Stop
        if (-not $match) {
            throw "Required dMSA schema attribute is absent: $name"
        }
        $attributes[$name] = [pscustomobject]@{
            LdapDisplayName = $match.lDAPDisplayName
            LinkId = $match.linkID
            AttributeSyntax = $match.attributeSyntax
            OmSyntax = $match.oMSyntax
        }
    }
    [pscustomobject]@{
        CreatedKdsRootKey = $createdKdsRootKey
        KdsRootKeyCount = @(Get-KdsRootKey -ErrorAction Stop).Count
        SchemaAttributes = $attributes
        SchemaVersion = (
            Get-ADObject `
                -Server 'ID-DC01.idlab.test' `
                -Identity $schemaContext `
                -Properties objectVersion `
                -ErrorAction Stop
        ).objectVersion
    }
}

function New-IdentityRodcAccount {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param()

    if ($env:COMPUTERNAME -ne 'ID-DC01') {
        throw 'RODC account creation is restricted to ID-DC01.'
    }
    Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.10' | Out-Null
    Set-IdentityDnsRegistration `
        -ExpectedIpAddress '172.28.30.10' `
        -Confirm:$false | Out-Null
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module ADDSDeployment -ErrorAction Stop
    $existing = Get-ADComputer `
        -Filter "Name -eq 'ID-RODC01'" `
        -Server 'ID-DC01.idlab.test' `
        -ErrorAction Stop
    if ($existing) {
        return [pscustomobject]@{ Changed = $false; Name = $existing.Name }
    }
    if (-not $PSCmdlet.ShouldProcess('ID-RODC01', 'Pre-create read-only domain controller account')) {
        return [pscustomobject]@{ Changed = $false; Name = 'ID-RODC01' }
    }
    Add-ADDSReadOnlyDomainControllerAccount `
        -DomainControllerAccountName 'ID-RODC01' `
        -DomainName 'idlab.test' `
        -SiteName 'Default-First-Site-Name' `
        -InstallDns `
        -ReplicationSourceDC 'ID-DC01.idlab.test' `
        -Force `
        -ErrorAction Stop
    [pscustomobject]@{ Changed = $true; Name = 'ID-RODC01' }
}

function Install-IdentityRodc {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][Management.Automation.PSCredential]$DomainCredential,
        [Parameter(Mandatory)][Security.SecureString]$SafeModeAdministratorPassword
    )

    if ($env:COMPUTERNAME -ne 'ID-RODC01') {
        throw 'RODC installation is restricted to ID-RODC01.'
    }
    $network = Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.11'
    Set-IdentityDnsRegistration `
        -ExpectedIpAddress '172.28.30.11' `
        -Confirm:$false | Out-Null
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.PartOfDomain) {
        if ($computer.Domain -ne 'idlab.test') {
            throw "ID-RODC01 belongs to an unexpected domain: $($computer.Domain)"
        }
        return [pscustomobject]@{
            Changed = $false
            RestartRequired = $false
            Network = $network
        }
    }
    if (-not $PSCmdlet.ShouldProcess('ID-RODC01', 'Install pre-created read-only domain controller')) {
        return [pscustomobject]@{ Changed = $false; RestartRequired = $false }
    }
    $feature = Install-WindowsFeature `
        -Name AD-Domain-Services, DNS, RSAT-AD-PowerShell `
        -IncludeManagementTools `
        -ErrorAction Stop
    if (-not $feature.Success) {
        throw 'RODC feature installation did not succeed.'
    }
    Import-Module ADDSDeployment -ErrorAction Stop
    Install-ADDSDomainController `
        -DomainName 'idlab.test' `
        -Credential $DomainCredential `
        -UseExistingAccount:$true `
        -ReplicationSourceDC 'ID-DC01.idlab.test' `
        -SafeModeAdministratorPassword $SafeModeAdministratorPassword `
        -NoRebootOnCompletion:$true `
        -Force:$true `
        -ErrorAction Stop
    [pscustomobject]@{
        Changed = $true
        RestartRequired = $true
        Network = $network
    }
}
