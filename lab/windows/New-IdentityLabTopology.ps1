Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'Test-IdentityLabPreflight.ps1')

function New-IdentityLabTopology {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [string]$SourceVmName = 'Bluex-Windows',
        [string]$SourceCheckpoint = 'tools-installed',
        [string]$GeneralizedVhdPath,
        [switch]$PlanOnly,
        [switch]$Apply
    )

    $plan = Test-IdentityLabPreflight `
        -RootPath $RootPath `
        -SourceVmName $SourceVmName `
        -SourceCheckpoint $SourceCheckpoint `
        -PlanOnly:(-not $Apply) `
        -Apply:$Apply
    $actions = @('Create private switch Bluex-Identity') + @(
        $plan.Nodes | ForEach-Object { "Create $($_.Name) from generalized template" }
    )
    $plan | Add-Member -NotePropertyName Actions -NotePropertyValue $actions
    $canonical = $plan | ConvertTo-Json -Depth 8 -Compress
    $plan | Add-Member -NotePropertyName PlanSha256 -NotePropertyValue (
        Get-IdentityLabSha256 -Value $canonical
    )
    if (-not $Apply) {
        return $plan
    }
    if (-not $GeneralizedVhdPath) {
        throw 'GeneralizedVhdPath is required with Apply.'
    }
    $resolvedVhd = [IO.Path]::GetFullPath($GeneralizedVhdPath)
    $allowedTemplate = [IO.Path]::GetFullPath(
        $plan.Template.GeneralizedExportPath
    ).TrimEnd('\') + '\'
    if (-not $resolvedVhd.StartsWith(
        $allowedTemplate,
        [StringComparison]::OrdinalIgnoreCase
    ) -or -not (Test-Path -LiteralPath $resolvedVhd)) {
        throw 'GeneralizedVhdPath must exist below GeneralizedTemplate.'
    }

    foreach ($path in @((Join-Path $plan.RootPath 'VMs'), (Join-Path $plan.RootPath 'Plans'))) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    $plan | ConvertTo-Json -Depth 8 | Set-Content `
        -LiteralPath (Join-Path $plan.RootPath 'Plans\topology-plan.json') `
        -Encoding UTF8
    if (-not (Get-VMSwitch -Name $plan.Network.Name -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($plan.Network.Name, 'Create private Hyper-V switch')) {
            New-VMSwitch -Name $plan.Network.Name -SwitchType Private | Out-Null
        }
    }
    foreach ($node in $plan.Nodes) {
        $nodePath = Join-Path (Join-Path $plan.RootPath 'VMs') $node.Name
        $diskPath = Join-Path $nodePath ($node.Name + '.vhdx')
        if ($PSCmdlet.ShouldProcess($node.Name, 'Create isolated Generation 2 VM')) {
            New-Item -ItemType Directory -Path $nodePath -Force | Out-Null
            New-VHD -Path $diskPath -ParentPath $resolvedVhd -Differencing | Out-Null
            New-VM `
                -Name $node.Name `
                -Generation 2 `
                -MemoryStartupBytes 4GB `
                -VHDPath $diskPath `
                -Path $nodePath `
                -SwitchName $plan.Network.Name | Out-Null
            Set-VMProcessor -VMName $node.Name -Count 2
            Set-VMFirmware -VMName $node.Name -EnableSecureBoot On
            Set-VMNetworkAdapter `
                -VMName $node.Name `
                -StaticMacAddress $node.MacAddress
            Set-VM -Name $node.Name -AutomaticCheckpointsEnabled $false
        }
    }
    return $plan
}
