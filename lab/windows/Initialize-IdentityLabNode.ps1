[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^172\.28\.30\.(10|11|20)$')]
    [string]$IpAddress,
    [Parameter(Mandatory)][ValidatePattern('^172\.28\.30\.10$')]
    [string]$DnsServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$adapter = Get-NetAdapter |
    Where-Object {
        $_.Status -eq 'Up' -and
        $_.InterfaceDescription -eq 'Microsoft Hyper-V Network Adapter'
    } |
    Select-Object -First 1
if (-not $adapter) {
    throw 'No active identity-lab network adapter was found.'
}

Get-NetIPAddress `
    -AddressFamily IPv4 `
    -IPAddress $IpAddress `
    -ErrorAction SilentlyContinue |
    Where-Object InterfaceIndex -ne $adapter.ifIndex |
    Remove-NetIPAddress -Confirm:$false -ErrorAction Stop

Get-NetIPAddress `
    -InterfaceIndex $adapter.ifIndex `
    -AddressFamily IPv4 `
    -ErrorAction SilentlyContinue |
    Where-Object PrefixOrigin -ne 'WellKnown' |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress `
    -InterfaceIndex $adapter.ifIndex `
    -IPAddress $IpAddress `
    -PrefixLength 24 `
    -AddressFamily IPv4 | Out-Null
Set-DnsClientServerAddress `
    -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses $DnsServer
foreach ($dnsClient in @(Get-DnsClient)) {
    $shouldRegister = $dnsClient.InterfaceIndex -eq $adapter.ifIndex
    if (-not $shouldRegister) {
        Set-DnsClientServerAddress `
            -InterfaceIndex $dnsClient.InterfaceIndex `
            -ResetServerAddresses `
            -ErrorAction SilentlyContinue
    }
    if ($dnsClient.RegisterThisConnectionsAddress -ne $shouldRegister) {
        Set-DnsClient `
            -InterfaceIndex $dnsClient.InterfaceIndex `
            -RegisterThisConnectionsAddress $shouldRegister
    }
}

$answerPaths = @(
    'C:\Windows\Panther\Unattend.xml',
    'C:\Windows\Panther\Unattend\Unattend.xml',
    'C:\Windows\System32\Sysprep\unattend.xml'
)
$existingAnswerPaths = @(
    $answerPaths | Where-Object { Test-Path -LiteralPath $_ }
)
foreach ($path in $existingAnswerPaths) {
    Remove-Item -LiteralPath $path -Force
}
foreach ($path in $answerPaths) {
    if (Test-Path -LiteralPath $path) {
        throw "Answer file remains after cleanup: $path"
    }
}

$configuredAddress = Get-NetIPAddress `
    -InterfaceIndex $adapter.ifIndex `
    -AddressFamily IPv4 |
    Where-Object IPAddress -eq $IpAddress
$defaultRoutes = @(
    Get-NetRoute `
        -InterfaceIndex $adapter.ifIndex `
        -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' `
        -ErrorAction SilentlyContinue
)
if (-not $configuredAddress -or $configuredAddress.PrefixLength -ne 24) {
    throw 'Static identity-lab address verification failed.'
}
if ($defaultRoutes.Count -ne 0) {
    throw 'Identity-lab adapter has an unexpected default route.'
}

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    IpAddress = $configuredAddress.IPAddress
    PrefixLength = $configuredAddress.PrefixLength
    DnsServers = (
        Get-DnsClientServerAddress `
            -InterfaceIndex $adapter.ifIndex `
            -AddressFamily IPv4
    ).ServerAddresses -join ','
    DefaultRoutes = $defaultRoutes.Count
    RemovedAnswerFiles = $existingAnswerPaths.Count
}
