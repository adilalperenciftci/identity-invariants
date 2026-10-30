Set-StrictMode -Version Latest

if (-not (Get-Command Assert-IdentityPrivateNetwork -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'Initialize-IdentityForest.ps1')
}

function Enable-IdentityKerberosOperationalLog {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $logName = (Get-IdentityForestPlan).KerberosOperationalLog
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Enable $logName")) {
        & wevtutil.exe sl $logName /e:true
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to enable $logName"
        }
    }
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    if (-not $log.IsEnabled) {
        throw "$logName is not enabled."
    }
    [pscustomobject]@{ LogName = $logName; Enabled = $log.IsEnabled }
}

function Join-IdentityMember {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][Management.Automation.PSCredential]$DomainCredential
    )

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'Member configuration is restricted to ID-SRV01.'
    }
    $network = Assert-IdentityPrivateNetwork -ExpectedIpAddress '172.28.30.20'
    Set-IdentityDnsRegistration `
        -ExpectedIpAddress '172.28.30.20' `
        -Confirm:$false | Out-Null
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.PartOfDomain) {
        if ($computer.Domain -ne 'idlab.test') {
            throw "ID-SRV01 belongs to an unexpected domain: $($computer.Domain)"
        }
        return [pscustomobject]@{
            Changed = $false
            RestartRequired = $false
            Network = $network
        }
    }
    if (-not $PSCmdlet.ShouldProcess('ID-SRV01', 'Join idlab.test')) {
        return [pscustomobject]@{ Changed = $false; RestartRequired = $false }
    }
    $feature = Install-WindowsFeature `
        -Name RSAT-AD-PowerShell `
        -IncludeManagementTools `
        -ErrorAction Stop
    if (-not $feature.Success) {
        throw 'RSAT AD PowerShell feature installation did not succeed.'
    }
    Add-Computer `
        -DomainName 'idlab.test' `
        -Credential $DomainCredential `
        -Options JoinWithNewName, AccountCreate `
        -Force `
        -ErrorAction Stop
    [pscustomobject]@{
        Changed = $true
        RestartRequired = $true
        Network = $network
    }
}
