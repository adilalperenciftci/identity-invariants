Set-StrictMode -Version Latest

function ConvertTo-Program1bUtcTimestamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParse(
        $Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
            [Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$parsed
    )) {
        throw "Timestamp is not a valid UTC value: $Value"
    }
    return $parsed.ToUniversalTime().ToString('o')
}

function New-Program1bObservationRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
        [string]$CaseId,
        [Parameter(Mandatory)][ValidateCount(1, 16)][string[]]$InvariantIds,
        [Parameter(Mandatory)]
        [ValidatePattern('^run-[a-z0-9][a-z0-9-]{0,31}$')]
        [string]$ReproductionId,
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
        [string]$CheckpointName,
        [Parameter(Mandatory)][Collections.IDictionary]$CheckpointIds,
        [Parameter(Mandatory)][string]$RestoreCompletedUtc,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SourceReference,
        [Parameter(Mandatory)]
        [ValidateSet('accept', 'reject', 'observe', 'skip', 'inconclusive')]
        [string]$Outcome,
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9][a-z0-9_]{0,95}$')]
        [string]$Reason,
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$BeforeDigest,
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$AfterDigest,
        [Parameter(Mandatory)][string]$StartedUtc,
        [Parameter(Mandatory)][string]$EndedUtc,
        [Parameter(Mandatory)][Collections.IDictionary]$Observation
    )

    $requiredHosts = @('ID-DC01', 'ID-RODC01', 'ID-SRV01')
    $observedHosts = @($CheckpointIds.Keys | ForEach-Object { [string]$_ })
    if (
        $observedHosts.Count -ne $requiredHosts.Count -or
        @($requiredHosts | Where-Object { $_ -notin $observedHosts }).Count -ne 0
    ) {
        throw 'Checkpoint map must contain ID-DC01, ID-RODC01, and ID-SRV01.'
    }
    $normalizedIds = [ordered]@{}
    foreach ($hostName in $requiredHosts) {
        $checkpointId = [guid]::Empty
        if (-not [guid]::TryParse([string]$CheckpointIds[$hostName], [ref]$checkpointId)) {
            throw "Checkpoint identifier is not a GUID for $hostName."
        }
        $normalizedIds[$hostName] = $checkpointId.ToString()
    }

    $restore = ConvertTo-Program1bUtcTimestamp -Value $RestoreCompletedUtc
    $started = ConvertTo-Program1bUtcTimestamp -Value $StartedUtc
    $ended = ConvertTo-Program1bUtcTimestamp -Value $EndedUtc
    if ([DateTime]$started -lt [DateTime]$restore -or [DateTime]$ended -lt [DateTime]$started) {
        throw 'Observation timestamps are outside the checkpoint restore window.'
    }

    [pscustomobject][ordered]@{
        CaseId = $CaseId
        InvariantIds = @($InvariantIds)
        Outcome = $Outcome
        Reason = $Reason
        BeforeDigest = $BeforeDigest
        AfterDigest = $AfterDigest
        StartedUtc = $started
        EndedUtc = $ended
        Metadata = [pscustomobject][ordered]@{
            Program = 'program1b'
            ReproductionId = $ReproductionId
            Checkpoint = [pscustomobject][ordered]@{
                Name = $CheckpointName
                VmIds = [pscustomobject]$normalizedIds
            }
            RestoreCompletedUtc = $restore
            SourceReference = $SourceReference
            Observation = [pscustomobject]$Observation
        }
    }
}

function ConvertTo-Program1bReplicationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Metadata,
        [Parameter(Mandatory)][ValidateCount(1, 64)][string[]]$Attributes
    )

    foreach ($attribute in $Attributes) {
        $entries = @(
            $Metadata |
            Where-Object { [string]$_.AttributeName -eq $attribute }
        )
        $values = @(
            foreach ($entry in $entries) {
                $value = $entry.AttributeValue
                if ($value -is [byte[]]) {
                    "binary-redacted:$($value.Length)"
                } elseif ($null -eq $value) {
                    'null'
                } elseif (
                    $value -is [string] -or
                    $value -is [ValueType]
                ) {
                    $value
                } elseif ($value.PSObject.Properties['DistinguishedName']) {
                    [string]$value.DistinguishedName
                } else {
                    [string]$value
                }
            }
        )
        $changeTimes = @(
            $entries |
            Where-Object { $null -ne $_.LastOriginatingChangeTime } |
            ForEach-Object {
                ([DateTime]$_.LastOriginatingChangeTime).
                    ToUniversalTime().ToString('o')
            } |
            Sort-Object -Unique
        )
        [pscustomobject][ordered]@{
            AttributeName = $attribute
            Present = $entries.Count -gt 0
            LinkValue = @($entries | Where-Object IsLinkValue).Count -gt 0
            Values = @($values | Sort-Object { [string]$_ } -Unique)
            Versions = @(
                $entries |
                ForEach-Object { [int]$_.Version } |
                Sort-Object -Unique
            )
            LocalChangeUsns = @(
                $entries |
                ForEach-Object { [long]$_.LocalChangeUsn } |
                Sort-Object -Unique
            )
            OriginatingChangeUsns = @(
                $entries |
                ForEach-Object { [long]$_.LastOriginatingChangeUsn } |
                Sort-Object -Unique
            )
            OriginatingServers = @(
                $entries |
                Where-Object {
                    $null -ne $_.LastOriginatingChangeDirectoryServerIdentity
                } |
                ForEach-Object {
                    [string]$_.LastOriginatingChangeDirectoryServerIdentity
                } |
                Sort-Object -Unique
            )
            LastOriginatingChangeUtc = $changeTimes
        }
    }
}

function Compare-Program1bReplicationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Before,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$After
    )

    $beforeByName = @{}
    foreach ($item in $Before) {
        $beforeByName[[string]$item.AttributeName] = $item
    }
    foreach ($item in $After) {
        $name = [string]$item.AttributeName
        $previous = $beforeByName[$name]
        $beforeJson = if ($null -eq $previous) {
            'null'
        } else {
            $previous | ConvertTo-Json -Depth 8 -Compress
        }
        $afterJson = $item | ConvertTo-Json -Depth 8 -Compress
        if ($beforeJson -ne $afterJson) {
            [pscustomobject][ordered]@{
                AttributeName = $name
                Before = $previous
                After = $item
            }
        }
    }
}
