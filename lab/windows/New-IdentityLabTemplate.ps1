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

    if ($PlanOnly -and $Apply) {
        throw 'PlanOnly and Apply are mutually exclusive.'
    }
    if ($Apply) {
        throw 'Template Apply mode is not implemented as one complete lifecycle.'
    }

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
    return $plan
}
