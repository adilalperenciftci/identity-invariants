Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'Test-IdentityLabPreflight.ps1')

function New-IdentityLabTemplate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [string]$SourceVmName = 'Bluex-Windows',
        [string]$SourceCheckpoint = 'tools-installed',
        [switch]$PlanOnly,
        [switch]$Apply
    )

    $plan = Test-IdentityLabPreflight `
        -RootPath $RootPath `
        -SourceVmName $SourceVmName `
        -SourceCheckpoint $SourceCheckpoint `
        -PlanOnly:(-not $Apply) `
        -Apply:$Apply
    $actions = @(
        'Export exact source checkpoint to TemplateSource',
        'Import exported copy as ID-TEMPLATE-WORK',
        'Generalize and shut down only ID-TEMPLATE-WORK',
        'Export generalized copy to GeneralizedTemplate',
        'Remove temporary imported VM while retaining the generalized export'
    )
    $plan | Add-Member -NotePropertyName Actions -NotePropertyValue $actions
    if (-not $Apply) {
        return $plan
    }

    foreach ($path in @(
        $plan.Template.SourceExportPath,
        $plan.Template.WorkingPath,
        $plan.Template.GeneralizedExportPath,
        (Join-Path $plan.RootPath 'Plans')
    )) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    $planPath = Join-Path $plan.RootPath 'Plans\template-plan.json'
    $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $planPath -Encoding UTF8
    if ($PSCmdlet.ShouldProcess(
        "$SourceVmName/$SourceCheckpoint",
        "Export checkpoint to $($plan.Template.SourceExportPath)"
    )) {
        $snapshot = Get-VMSnapshot -VMName $SourceVmName -Name $SourceCheckpoint
        Export-VMSnapshot -VMSnapshot $snapshot -Path $plan.Template.SourceExportPath
    }
    return $plan
}
