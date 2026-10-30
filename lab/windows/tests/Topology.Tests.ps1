$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $labRoot 'New-IdentityLabTemplate.ps1')
. (Join-Path $labRoot 'New-IdentityLabTopology.ps1')

function Get-VM { param($Name, $ErrorAction) }
function Get-VMSnapshot { param($VMName, $Name, $ErrorAction) }
function Get-VMSwitch { param($Name, $ErrorAction) }

Describe 'Identity lab topology plan' {
    BeforeEach {
        Mock Get-VM {
            param($Name, $ErrorAction)
            if ($Name -eq 'Bluex-Windows') {
                [pscustomobject]@{ Name = 'Bluex-Windows'; Generation = 2 }
            }
        }
        Mock Get-VMSnapshot {
            param($VMName, $Name, $ErrorAction)
            [pscustomobject]@{ Name = 'tools-installed'; VMName = 'Bluex-Windows' }
        }
        Mock Get-VMSwitch { param($Name, $ErrorAction); $null }
    }

    It 'uses plan-only mode by default for template work' {
        $plan = New-IdentityLabTemplate `
            -RootPath 'C:\Hyper-V\BluexLab\Identity' `
            -SourceVmName 'Bluex-Windows'

        $plan.Mode | Should Be 'PlanOnly'
        $plan.Actions.Count | Should BeGreaterThan 0
        Assert-MockCalled Get-VM -Times 4
    }

    It 'uses plan-only mode by default for topology work' {
        $plan = New-IdentityLabTopology `
            -RootPath 'C:\Hyper-V\BluexLab\Identity' `
            -SourceVmName 'Bluex-Windows'

        $plan.Mode | Should Be 'PlanOnly'
        $plan.Nodes.Count | Should Be 3
        $plan.PlanSha256 | Should Match '^[0-9a-f]{64}$'
    }

    It 'uses exact unique node identities' {
        $plan = New-IdentityLabTopology `
            -RootPath 'C:\Hyper-V\BluexLab\Identity' `
            -SourceVmName 'Bluex-Windows'

        @($plan.Nodes.Name | Select-Object -Unique).Count | Should Be 3
        @($plan.Nodes.IpAddress | Select-Object -Unique).Count | Should Be 3
        @($plan.Nodes.MacAddress | Select-Object -Unique).Count | Should Be 3
        ($plan.Nodes.Name -join ',') | Should Be 'ID-DC01,ID-RODC01,ID-SRV01'
    }
}
