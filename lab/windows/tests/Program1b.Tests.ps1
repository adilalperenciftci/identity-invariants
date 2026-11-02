$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$followupPath = Join-Path $labRoot 'Invoke-Program1bConformance.ps1'
if (Test-Path -LiteralPath $followupPath) {
    . $followupPath
}

Describe 'Program 1b evidence envelope' {
    It 'binds an observation to one independent run and all baseline checkpoints' {
        $record = New-Program1bObservationRecord `
            -CaseId 'dmsa-rodc-local-state-run-a' `
            -InvariantIds @('DMSA-RWDC-001') `
            -ReproductionId 'run-a' `
            -CheckpointName 'dmsa-baseline' `
            -CheckpointIds ([ordered]@{
                'ID-DC01' = 'dc3aeb0a-3772-41e5-8d28-5879378688e8'
                'ID-RODC01' = 'cb163cc9-c707-4260-a82d-56d4d7f3fd89'
                'ID-SRV01' = '0047ee56-37f8-42dd-95df-bd5df9276597'
            }) `
            -RestoreCompletedUtc '2026-11-02T01:00:00Z' `
            -SourceReference 'DMSA-RWDC-001/windows-server-2025-dmsa' `
            -Outcome 'observe' `
            -Reason 'rodc_local_transition_persisted' `
            -BeforeDigest ('a' * 64) `
            -AfterDigest ('b' * 64) `
            -StartedUtc '2026-11-02T01:01:00Z' `
            -EndedUtc '2026-11-02T01:02:00Z' `
            -Observation ([ordered]@{ State = 1; ServiceDecision = 'unchanged' })

        $record.CaseId | Should Be 'dmsa-rodc-local-state-run-a'
        $record.InvariantIds | Should Be @('DMSA-RWDC-001')
        $record.Metadata.Program | Should Be 'program1b'
        $record.Metadata.ReproductionId | Should Be 'run-a'
        $record.Metadata.Checkpoint.Name | Should Be 'dmsa-baseline'
        @($record.Metadata.Checkpoint.VmIds.PSObject.Properties).Count | Should Be 3
        $record.Metadata.RestoreCompletedUtc | Should Be '2026-11-02T01:00:00.0000000Z'
        $record.Metadata.SourceReference | Should Be (
            'DMSA-RWDC-001/windows-server-2025-dmsa'
        )
        $record.Metadata.Observation.State | Should Be 1
    }

    It 'rejects a record that omits one lab checkpoint identifier' {
        {
            New-Program1bObservationRecord `
                -CaseId 'dmsa-rodc-local-state-run-a' `
                -InvariantIds @('DMSA-RWDC-001') `
                -ReproductionId 'run-a' `
                -CheckpointName 'dmsa-baseline' `
                -CheckpointIds ([ordered]@{
                    'ID-DC01' = 'dc3aeb0a-3772-41e5-8d28-5879378688e8'
                    'ID-RODC01' = 'cb163cc9-c707-4260-a82d-56d4d7f3fd89'
                }) `
                -RestoreCompletedUtc '2026-11-02T01:00:00Z' `
                -SourceReference 'DMSA-RWDC-001/windows-server-2025-dmsa' `
                -Outcome 'observe' `
                -Reason 'rodc_local_transition_persisted' `
                -BeforeDigest ('a' * 64) `
                -AfterDigest ('b' * 64) `
                -StartedUtc '2026-11-02T01:01:00Z' `
                -EndedUtc '2026-11-02T01:02:00Z' `
                -Observation ([ordered]@{ State = 1 })
        } | Should Throw 'Checkpoint map must contain ID-DC01, ID-RODC01, and ID-SRV01.'
    }
}

Describe 'Program 1b replication metadata normalization' {
    It 'identifies changed migration attributes without retaining binary values' {
        $before = @(
            [pscustomobject]@{
                AttributeName = 'msDS-DelegatedMSAState'
                AttributeValue = 0
                Version = 1
                IsLinkValue = $false
                LastOriginatingChangeTime = [DateTime]'2026-11-02T01:00:00Z'
                LastOriginatingChangeDirectoryServerIdentity = 'ID-DC01'
                LastOriginatingChangeUsn = 100
                LocalChangeUsn = 100
            },
            [pscustomobject]@{
                AttributeName = 'msDS-GroupMSAMembership'
                AttributeValue = [byte[]](1, 2, 3, 4)
                Version = 1
                IsLinkValue = $false
                LastOriginatingChangeTime = [DateTime]'2026-11-02T01:00:00Z'
                LastOriginatingChangeDirectoryServerIdentity = 'ID-DC01'
                LastOriginatingChangeUsn = 101
                LocalChangeUsn = 101
            }
        )
        $after = @(
            [pscustomobject]@{
                AttributeName = 'msDS-DelegatedMSAState'
                AttributeValue = 1
                Version = 2
                IsLinkValue = $false
                LastOriginatingChangeTime = [DateTime]'2026-11-02T01:02:00Z'
                LastOriginatingChangeDirectoryServerIdentity = 'ID-RODC01'
                LastOriginatingChangeUsn = 200
                LocalChangeUsn = 200
            },
            [pscustomobject]@{
                AttributeName = 'msDS-ManagedAccountPrecededByLink'
                AttributeValue = 'CN=svc-legacy,OU=IdentityLab,DC=idlab,DC=test'
                Version = 1
                IsLinkValue = $true
                LastOriginatingChangeTime = [DateTime]'2026-11-02T01:02:01Z'
                LastOriginatingChangeDirectoryServerIdentity = 'ID-RODC01'
                LastOriginatingChangeUsn = 201
                LocalChangeUsn = 201
            },
            $before[1]
        )

        $beforeState = ConvertTo-Program1bReplicationState `
            -Metadata $before `
            -Attributes @(
                'msDS-DelegatedMSAState',
                'msDS-ManagedAccountPrecededByLink',
                'msDS-GroupMSAMembership'
            )
        $afterState = ConvertTo-Program1bReplicationState `
            -Metadata $after `
            -Attributes @(
                'msDS-DelegatedMSAState',
                'msDS-ManagedAccountPrecededByLink',
                'msDS-GroupMSAMembership'
            )
        $changes = Compare-Program1bReplicationState `
            -Before $beforeState `
            -After $afterState

        @($changes | ForEach-Object AttributeName) | Should Be @(
            'msDS-DelegatedMSAState',
            'msDS-ManagedAccountPrecededByLink'
        )
        ($afterState | Where-Object AttributeName -eq 'msDS-DelegatedMSAState').Values |
            Should Be @(1)
        ($afterState | Where-Object AttributeName -eq 'msDS-GroupMSAMembership').Values |
            Should Be @('binary-redacted:4')
    }
}
