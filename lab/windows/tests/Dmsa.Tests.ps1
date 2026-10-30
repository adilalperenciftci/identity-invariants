$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $labRoot 'Invoke-DmsaInvariant.ps1')
. (Join-Path $labRoot 'Export-IdentityEvidence.ps1')

function Get-ADUser {
    param($Filter, $Server, $ErrorAction)
}

Describe 'dMSA lifecycle contract' {
    It 'defines the supported state transitions' {
        $plan = Get-DmsaLifecyclePlan

        $plan.DmsaContainer | Should Be (
            'CN=Managed Service Accounts,DC=idlab,DC=test'
        )
        $plan.BuildDefaultState | Should Be 0
        $plan.DocumentedStandaloneState | Should Be 3
        $plan.Standalone.TargetState | Should Be 3
        $plan.Start.TargetState | Should Be 1
        $plan.Complete.RequiredState | Should Be 1
        $plan.Complete.TargetState | Should Be 2
        $plan.Undo.RequiredState | Should Be 1
        $plan.Undo.TargetState | Should Be 0
        $plan.Reset.TargetState | Should Be 0
    }

    It 'rejects completion before migration start without mutation' {
        $decision = Test-DmsaTransition -CurrentState 0 -Phase Complete

        $decision.Allowed | Should Be $false
        $decision.CurrentState | Should Be 0
        $decision.TargetState | Should Be 2
        $decision.Reason | Should Be 'invalid_transition'
    }

    It 'permits the documented started to completed transition' {
        $decision = Test-DmsaTransition -CurrentState 1 -Phase Complete

        $decision.Allowed | Should Be $true
        $decision.TargetState | Should Be 2
        $decision.Reason | Should Be 'accepted'
    }

    It 'binds cases to every dMSA invariant' {
        $plan = Get-DmsaLifecyclePlan
        $ids = @($plan.Cases | ForEach-Object { $_.InvariantIds } | Select-Object -Unique)

        foreach ($expected in @(
            'DMSA-LINK-001',
            'DMSA-STATE-001',
            'DMSA-ACL-001',
            'DMSA-SPN-001',
            'DMSA-MACHINE-001',
            'DMSA-RWDC-001',
            'DMSA-EVENT-001',
            'DMSA-ROLLBACK-001'
        )) {
            ($ids -contains $expected) | Should Be $true
        }
    }

    It 'resolves the superseded account to its distinguished name' {
        Mock Get-ADUser {
            [pscustomobject]@{
                DistinguishedName = 'CN=svc-legacy,OU=IdentityLab,DC=idlab,DC=test'
            }
        }

        $resolved = Resolve-DmsaLegacyDistinguishedName `
            -LegacyAccount 'svc-legacy' `
            -Server 'ID-DC01.idlab.test'

        $resolved | Should Be 'CN=svc-legacy,OU=IdentityLab,DC=idlab,DC=test'
        Assert-MockCalled Get-ADUser -Times 1 -ParameterFilter {
            $Filter -eq "SamAccountName -eq 'svc-legacy'" -and
            $Server -eq 'ID-DC01.idlab.test'
        }
    }

    It 'normalizes dMSA audit events without retaining event messages' {
        Mock Get-WinEvent {
            [pscustomobject]@{ Id = 309; RecordId = 44; TimeCreated = [datetime]'2026-10-30T10:00:03Z' }
            [pscustomobject]@{ Id = 307; RecordId = 42; TimeCreated = [datetime]'2026-10-30T10:00:01Z' }
            [pscustomobject]@{ Id = 307; RecordId = 43; TimeCreated = [datetime]'2026-10-30T10:00:02Z' }
        }

        $result = Get-DmsaAuditEventObservation `
            -StartTime ([datetime]'2026-10-30T09:59:59Z')

        ($result.EventIds -join ',') | Should Be '307,309'
        $result.EventCounts.'307' | Should Be 2
        $result.EventCounts.'308' | Should Be 0
        $result.EventCounts.'309' | Should Be 1
        ($result.RecordIds -join ',') | Should Be '42,43,44'
        ($result.PSObject.Properties.Name -contains 'Message') | Should Be $false
    }

    It 'represents an empty audit window without a StrictMode error' {
        Mock Get-WinEvent { @() }

        $result = Get-DmsaAuditEventObservation `
            -StartTime ([datetime]'2026-10-30T09:59:59Z')

        $result.Count | Should Be 0
        @($result.EventIds).Count | Should Be 0
        @($result.RecordIds).Count | Should Be 0
        $result.EventCounts.'307' | Should Be 0
        $result.EventCounts.'308' | Should Be 0
        $result.EventCounts.'309' | Should Be 0
    }

    It 'restricts service-logon observation to the enrolled member' {
        $secureValue = ConvertTo-SecureString ('x' * 32) -AsPlainText -Force

        $message = $null
        try {
            Invoke-DmsaServiceLogonObservation -AccountPassword $secureValue
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }
        $message | Should Match 'restricted to ID-SRV01'
    }

    It 'adds a service-logon SID without replacing existing principals' {
        $result = Merge-DmsaUserRightSid `
            -ExistingValue '*S-1-5-80-0,*S-1-5-99-0' `
            -AccountSid 'S-1-5-21-100-200-300-400'

        $result.Changed | Should Be $true
        $result.Value | Should Be (
            '*S-1-5-80-0,*S-1-5-99-0,*S-1-5-21-100-200-300-400'
        )
    }

    It 'does not duplicate an existing service-logon SID' {
        $result = Merge-DmsaUserRightSid `
            -ExistingValue '*S-1-5-80-0,*S-1-5-21-100-200-300-400' `
            -AccountSid 'S-1-5-21-100-200-300-400'

        $result.Changed | Should Be $false
        $result.Value | Should Be '*S-1-5-80-0,*S-1-5-21-100-200-300-400'
    }

    It 'selects the Windows Kerberos tool independently of PATH order' {
        $result = Get-DmsaSystemKlistPath

        $result | Should Be (Join-Path $env:SystemRoot 'System32\klist.exe')
    }

    It 'reports declined mutation without claiming an observation' {
        $document = [pscustomobject]@{
            Dmsa = [pscustomobject]@{ State = 0 }
        }
        Mock Import-Module {}
        Mock Get-DmsaGraphSnapshot {
            [pscustomobject]@{
                Digest = ('a' * 64)
                Document = $document
            }
        }
        Mock Resolve-DmsaLegacyDistinguishedName {
            'CN=svc-legacy,OU=IdentityLab,DC=idlab,DC=test'
        }
        Mock Start-ADServiceAccountMigration {}
        Mock Get-WinEvent { @() }

        $result = Invoke-DmsaInvariantCase `
            -CaseId 'dmsa-start-whatif' `
            -Phase Start `
            -WhatIf

        $result.Outcome | Should Be 'skip'
        $result.Reason | Should Be 'mutation_not_approved'
        $result.BeforeDigest | Should Be ('a' * 64)
        $result.AfterDigest | Should Be ('a' * 64)
        $result.MutationAttempted | Should Be $false
        Assert-MockCalled Start-ADServiceAccountMigration -Times 0 -Scope It
        Assert-MockCalled Resolve-DmsaLegacyDistinguishedName -Times 0 -Scope It
        Assert-MockCalled Get-WinEvent -Times 0 -Scope It
        Assert-MockCalled Get-DmsaGraphSnapshot -Times 1 -Scope It
    }

    It 'exports only redacted records with a sealed manifest' {
        $root = Join-Path $TestDrive 'evidence'
        New-Item -ItemType Directory -Path $root | Out-Null
        $artifact = Join-Path $root 'graph.json'
        '{"state":1}' | Set-Content -LiteralPath $artifact -Encoding UTF8
        $records = @(
            [pscustomobject]@{
                CaseId = 'dmsa-started-to-complete'
                InvariantIds = @('DMSA-STATE-001')
                Outcome = 'observe'
                Reason = 'accepted'
                BeforeDigest = ('a' * 64)
                AfterDigest = ('b' * 64)
                Metadata = [ordered]@{ Build = 26100; State = 2 }
            }
        )

        $manifest = Export-IdentityEvidence `
            -RunId 'task7-unit' `
            -OutputPath $root `
            -Records $records `
            -ArtifactPaths @($artifact)

        $manifest.RecordCount | Should Be 1
        $manifest.LedgerSha256 | Should Match '^[0-9a-f]{64}$'
        Test-Path -LiteralPath $manifest.Path | Should Be $true
        (Get-Content -LiteralPath $manifest.LedgerPath -Raw) | Should Not Match (
            'password|private_key|raw_ticket'
        )
    }
}
