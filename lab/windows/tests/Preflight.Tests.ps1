$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $labRoot 'Test-IdentityLabPreflight.ps1')

function Get-VM { param($Name, $ErrorAction) }
function Get-VMSnapshot { param($VMName, $Name, $ErrorAction) }
function Get-VMSwitch { param($Name, $ErrorAction) }

Describe 'Identity lab preflight' {
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

    It 'emits an exact plan without selecting an external switch' {
        $plan = Test-IdentityLabPreflight `
            -RootPath 'C:\Hyper-V\BluexLab\Identity' `
            -SourceVmName 'Bluex-Windows'

        $plan.Mode | Should Be 'PlanOnly'
        $plan.Network.Name | Should Be 'Bluex-Identity'
        $plan.Network.SwitchType | Should Be 'Private'
        $plan.Network.ContainsNat | Should Be $false
        ($plan.Nodes.Name -join ',') | Should Be 'ID-DC01,ID-RODC01,ID-SRV01'
        ($plan.Nodes.IpAddress -join ',') | Should Be (
            '172.28.30.10,172.28.30.11,172.28.30.20'
        )
        @($plan.Nodes.MacAddress | Select-Object -Unique).Count | Should Be 3
    }

    It 'keeps every mutable path below the identity root' {
        $root = 'C:\Hyper-V\BluexLab\Identity'
        $plan = Test-IdentityLabPreflight -RootPath $root -SourceVmName 'Bluex-Windows'
        $resolvedRoot = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'

        foreach ($path in @($plan.MutablePaths)) {
            [IO.Path]::GetFullPath($path).StartsWith(
                $resolvedRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) | Should Be $true
        }
    }

    It 'never includes the source VM path or name as a mutation target' {
        $plan = Test-IdentityLabPreflight `
            -RootPath 'C:\Hyper-V\BluexLab\Identity' `
            -SourceVmName 'Bluex-Windows'

        $plan.Source.ReadOnly | Should Be $true
        ($plan.Nodes.Name -contains 'Bluex-Windows') | Should Be $false
        ($plan.MutablePaths -join '|') | Should Not Match 'Bluex-Windows'
    }

    It 'stops when an exact target VM already exists' {
        Mock Get-VM {
            param($Name, $ErrorAction)
            if ($Name -in @('Bluex-Windows', 'ID-DC01')) {
                [pscustomobject]@{ Name = $Name; Generation = 2 }
            }
        }

        $message = $null
        try {
            Test-IdentityLabPreflight `
                -RootPath 'C:\Hyper-V\BluexLab\Identity' `
                -SourceVmName 'Bluex-Windows'
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }
        $message | Should Match 'already exists'
    }

    It 'stops if the named lab switch exists with a non-private type' {
        Mock Get-VMSwitch {
            param($Name, $ErrorAction)
            [pscustomobject]@{ Name = 'Bluex-Identity'; SwitchType = 'External' }
        }

        $message = $null
        try {
            Test-IdentityLabPreflight `
                -RootPath 'C:\Hyper-V\BluexLab\Identity' `
                -SourceVmName 'Bluex-Windows'
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }
        $message | Should Match 'must be Private'
    }
}
