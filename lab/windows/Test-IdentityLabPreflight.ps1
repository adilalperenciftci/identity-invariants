Set-StrictMode -Version Latest

function Get-IdentityLabSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Assert-IdentityLabChildPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$Path
    )

    $root = [IO.Path]::GetFullPath($RootPath).TrimEnd('\') + '\'
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not $candidate.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Mutable path escapes identity root: $candidate"
    }
    return $candidate
}

function Test-IdentityLabPreflight {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [string]$SourceVmName = 'Bluex-Windows',
        [string]$SourceCheckpoint = 'tools-installed',
        [switch]$PlanOnly,
        [switch]$Apply
    )

    if ($PlanOnly -and $Apply) {
        throw 'PlanOnly and Apply are mutually exclusive.'
    }
    $mode = if ($Apply) { 'Apply' } else { 'PlanOnly' }
    $allowedRoot = [IO.Path]::GetFullPath('C:\Hyper-V\BluexLab\Identity').TrimEnd('\')
    $resolvedRoot = [IO.Path]::GetFullPath($RootPath).TrimEnd('\')
    if ($resolvedRoot -ne $allowedRoot -and -not $resolvedRoot.StartsWith(
        $allowedRoot + '\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "RootPath must remain under $allowedRoot"
    }

    $sourceVm = Get-VM -Name $SourceVmName -ErrorAction SilentlyContinue
    if (-not $sourceVm) {
        throw "Source VM not found: $SourceVmName"
    }
    if ($sourceVm.Generation -ne 2) {
        throw 'Source VM must be Generation 2.'
    }
    $sourceSnapshot = Get-VMSnapshot `
        -VMName $SourceVmName `
        -Name $SourceCheckpoint `
        -ErrorAction SilentlyContinue
    if (-not $sourceSnapshot) {
        throw "Source checkpoint not found: $SourceCheckpoint"
    }

    $nodeDefinitions = @(
        [ordered]@{
            Name = 'ID-DC01'
            IpAddress = '172.28.30.10'
            MacAddress = '00155D1E300A'
            Role = 'RWDC,DNS,KDC'
        },
        [ordered]@{
            Name = 'ID-RODC01'
            IpAddress = '172.28.30.11'
            MacAddress = '00155D1E300B'
            Role = 'RODC,DNS,KDC'
        },
        [ordered]@{
            Name = 'ID-SRV01'
            IpAddress = '172.28.30.20'
            MacAddress = '00155D1E3014'
            Role = 'Member,dMSA consumer'
        }
    )
    foreach ($node in $nodeDefinitions) {
        if (Get-VM -Name $node.Name -ErrorAction SilentlyContinue) {
            throw "Target VM already exists: $($node.Name)"
        }
    }
    $names = @($nodeDefinitions | ForEach-Object { $_['Name'] })
    $addresses = @($nodeDefinitions | ForEach-Object { $_['IpAddress'] })
    $macAddresses = @($nodeDefinitions | ForEach-Object { $_['MacAddress'] })
    if (@($names | Select-Object -Unique).Count -ne $nodeDefinitions.Count -or
        @($addresses | Select-Object -Unique).Count -ne $nodeDefinitions.Count -or
        @($macAddresses | Select-Object -Unique).Count -ne $nodeDefinitions.Count) {
        throw 'Identity lab node names, addresses, and MAC addresses must be unique.'
    }

    $switch = Get-VMSwitch -Name 'Bluex-Identity' -ErrorAction SilentlyContinue
    if ($switch -and $switch.SwitchType -ne 'Private') {
        throw 'Existing Bluex-Identity switch must be Private.'
    }

    $templateSource = Assert-IdentityLabChildPath $resolvedRoot (Join-Path $resolvedRoot 'TemplateSource')
    $templateWork = Assert-IdentityLabChildPath $resolvedRoot (Join-Path $resolvedRoot 'TemplateWork')
    $templateExport = Assert-IdentityLabChildPath $resolvedRoot (Join-Path $resolvedRoot 'GeneralizedTemplate')
    $vmRoot = Assert-IdentityLabChildPath $resolvedRoot (Join-Path $resolvedRoot 'VMs')
    $planRoot = Assert-IdentityLabChildPath $resolvedRoot (Join-Path $resolvedRoot 'Plans')
    $mutablePaths = @($templateSource, $templateWork, $templateExport, $vmRoot, $planRoot)
    foreach ($node in $nodeDefinitions) {
        $mutablePaths += Assert-IdentityLabChildPath $resolvedRoot (Join-Path $vmRoot $node.Name)
    }

    return [pscustomobject][ordered]@{
        FormatVersion = 1
        Mode = $mode
        RootPath = $resolvedRoot
        Source = [pscustomobject][ordered]@{
            VmName = $SourceVmName
            Checkpoint = $SourceCheckpoint
            ReadOnly = $true
        }
        Network = [pscustomobject][ordered]@{
            Name = 'Bluex-Identity'
            SwitchType = 'Private'
            Subnet = '172.28.30.0/24'
            ContainsNat = $false
        }
        Template = [pscustomobject][ordered]@{
            SourceExportPath = $templateSource
            WorkingPath = $templateWork
            GeneralizedExportPath = $templateExport
            TemporaryVmName = 'ID-TEMPLATE-WORK'
        }
        Nodes = @($nodeDefinitions | ForEach-Object { [pscustomobject]$_ })
        MutablePaths = $mutablePaths
    }
}
