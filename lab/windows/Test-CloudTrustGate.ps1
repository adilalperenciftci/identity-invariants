Set-StrictMode -Version Latest

function Get-CloudTrustGatePlan {
    [CmdletBinding()]
    param()

    [pscustomobject][ordered]@{
        FormatVersion = 1
        ReadOnly = $true
        Rwdc = 'ID-DC01.idlab.test'
        Windows11Client = 'ID-CL01'
        AzureAdKerberosSamAccountName = 'AzureADKerberos$'
        RequiredChecks = @(
            'server-2025-rwdc'
            'azureadkerberos-object'
            'password-replication-policy'
            'cloud-trust-policy'
            'windows-11-client'
            'line-of-sight'
            'partial-tgt'
        )
    }
}

function Test-CloudTrustPasswordReplicationPolicy {
    [CmdletBinding()]
    param([AllowNull()][object]$DirectoryObject)

    if ($null -eq $DirectoryObject) {
        return $false
    }
    $properties = @($DirectoryObject.PSObject.Properties.Name)
    if (
        'msDS-RevealOnDemandGroup' -notin $properties -or
        'msDS-NeverRevealGroup' -notin $properties
    ) {
        return $false
    }
    return (
        @($DirectoryObject.'msDS-RevealOnDemandGroup').Count -gt 0 -and
        @($DirectoryObject.'msDS-NeverRevealGroup').Count -gt 0
    )
}

function Test-CloudTrustInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Inventory)

    $required = @(
        'Server2025Rwdc'
        'AzureAdKerberosObject'
        'PasswordReplicationPolicyIntact'
        'CloudTrustPolicySelected'
        'CertificateTrustPolicySelected'
        'Windows11Client'
        'ClientJoined'
        'LineOfSight'
        'PartialTgt'
    )
    foreach ($name in $required) {
        if (-not $Inventory.Contains($name) -or $Inventory[$name] -isnot [bool]) {
            throw "Cloud trust inventory requires boolean field: $name"
        }
    }
    $reasons = @()
    if (-not $Inventory.Server2025Rwdc) {
        $reasons += 'server_2025_rwdc_missing'
    }
    if (-not $Inventory.AzureAdKerberosObject) {
        $reasons += 'cloud_kerberos_object_missing'
    }
    if (-not $Inventory.PasswordReplicationPolicyIntact) {
        $reasons += 'password_replication_policy_unverified'
    }
    if (-not $Inventory.CloudTrustPolicySelected) {
        $reasons += 'cloud_trust_policy_unverified'
    }
    if ($Inventory.CertificateTrustPolicySelected) {
        $reasons += 'certificate_trust_precedence'
    }
    if (-not $Inventory.Windows11Client -or -not $Inventory.ClientJoined) {
        $reasons += 'windows_11_client_missing'
    }
    if (-not $Inventory.LineOfSight) {
        $reasons += 'line_of_sight_missing'
    }
    if (-not $Inventory.PartialTgt) {
        $reasons += 'partial_tgt_missing'
    }
    [pscustomobject][ordered]@{
        Outcome = if ($reasons.Count -eq 0) { 'pass' } else { 'skip' }
        ReasonCodes = @($reasons)
        NetworkRequestCount = 0
        Inventory = [pscustomobject][ordered]@{
            Server2025Rwdc = $Inventory.Server2025Rwdc
            AzureAdKerberosObject = $Inventory.AzureAdKerberosObject
            PasswordReplicationPolicyIntact = $Inventory.PasswordReplicationPolicyIntact
            CloudTrustPolicySelected = $Inventory.CloudTrustPolicySelected
            CertificateTrustPolicySelected = $Inventory.CertificateTrustPolicySelected
            Windows11Client = $Inventory.Windows11Client
            ClientJoined = $Inventory.ClientJoined
            LineOfSight = $Inventory.LineOfSight
            PartialTgt = $Inventory.PartialTgt
        }
    }
}

function Get-CloudTrustInventory {
    [CmdletBinding()]
    param()

    $plan = Get-CloudTrustGatePlan
    $inventory = [ordered]@{
        Server2025Rwdc = $false
        AzureAdKerberosObject = $false
        PasswordReplicationPolicyIntact = $false
        CloudTrustPolicySelected = $false
        CertificateTrustPolicySelected = $false
        Windows11Client = $false
        ClientJoined = $false
        LineOfSight = $false
        PartialTgt = $false
    }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $rwdc = Get-ADDomainController `
            -Identity $plan.Rwdc `
            -Server $plan.Rwdc `
            -ErrorAction Stop
        $rwdcComputer = Get-ADComputer `
            -Identity $rwdc.ComputerObjectDN `
            -Properties OperatingSystem `
            -Server $plan.Rwdc `
            -ErrorAction Stop
        $azureObject = Get-ADComputer `
            -LDAPFilter "(sAMAccountName=$($plan.AzureAdKerberosSamAccountName))" `
            -Properties msDS-RevealOnDemandGroup,msDS-NeverRevealGroup `
            -Server $plan.Rwdc `
            -ErrorAction Stop
        $client = Get-ADComputer `
            -Filter "Name -eq '$($plan.Windows11Client)'" `
            -Properties OperatingSystem,Enabled `
            -Server $plan.Rwdc `
            -ErrorAction Stop
    } catch {
        $Error.Clear()
        return $inventory
    }
    $inventory.Server2025Rwdc = (
        -not $rwdc.IsReadOnly -and
        $rwdcComputer.OperatingSystem -match 'Windows Server 2025'
    )
    $inventory.AzureAdKerberosObject = $null -ne $azureObject
    $inventory.PasswordReplicationPolicyIntact = (
        Test-CloudTrustPasswordReplicationPolicy -DirectoryObject $azureObject
    )
    $inventory.Windows11Client = (
        $null -ne $client -and $client.OperatingSystem -match 'Windows 11'
    )
    $isExpectedClient = $env:COMPUTERNAME -eq $plan.Windows11Client
    if ($isExpectedClient) {
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
        $cloudTrust = Get-ItemPropertyValue `
            -LiteralPath $policyPath `
            -Name 'UseCloudTrustForOnPremAuth' `
            -ErrorAction SilentlyContinue
        $certificateTrust = Get-ItemPropertyValue `
            -LiteralPath $policyPath `
            -Name 'UseCertificateForOnPremAuth' `
            -ErrorAction SilentlyContinue
        $inventory.CloudTrustPolicySelected = $cloudTrust -eq 1
        $inventory.CertificateTrustPolicySelected = $certificateTrust -eq 1
        try {
            $inventory.ClientJoined = Test-ComputerSecureChannel `
                -Server $plan.Rwdc `
                -ErrorAction Stop
        } catch {
            $inventory.ClientJoined = $false
            $Error.Clear()
        }
    }
    try {
        $inventory.LineOfSight = (
            Get-ADDomain -Server $plan.Rwdc -ErrorAction Stop
        ).DNSRoot -eq 'idlab.test'
    } catch {
        $inventory.LineOfSight = $false
        $Error.Clear()
    }
    if ($isExpectedClient) {
        $cloudDebug = & (Join-Path $env:SystemRoot 'System32\klist.exe') cloud_debug 2>&1
        $inventory.PartialTgt = (
            $LASTEXITCODE -eq 0 -and $cloudDebug -match 'Partial TGT'
        )
    }
    return $inventory
}

function Test-CloudTrustGate {
    [CmdletBinding()]
    param()

    Test-CloudTrustInventory -Inventory (Get-CloudTrustInventory)
}
