Set-StrictMode -Version Latest

if (-not (Get-Command Get-DmsaSha256 -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'Invoke-DmsaInvariant.ps1')
}

function Assert-IdentityEvidenceRedacted {
    [CmdletBinding()]
    param(
        [AllowNull()]$Value,
        [string]$Path = 'record'
    )

    $forbidden = @(
        'password',
        'privatekey',
        'rawticket',
        'sessionkey',
        'credential',
        'accesstoken',
        'refreshtoken'
    )
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        if ($Value -is [string] -and $Value -match '-----BEGIN |-----END ') {
            throw "Prohibited value shape at $Path"
        }
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $normalized = ([string]$key).ToLowerInvariant() -replace '[^a-z0-9]', ''
            foreach ($part in $forbidden) {
                if ($normalized.Contains($part)) {
                    throw "Prohibited evidence key at $Path.$key"
                }
            }
            Assert-IdentityEvidenceRedacted -Value $Value[$key] -Path "$Path.$key"
        }
        return
    }
    if ($Value -is [Collections.IEnumerable]) {
        $index = 0
        foreach ($item in $Value) {
            Assert-IdentityEvidenceRedacted -Value $item -Path "$Path[$index]"
            $index++
        }
        return
    }
    $properties = @($Value.PSObject.Properties | Where-Object IsGettable)
    foreach ($property in $properties) {
        $normalized = $property.Name.ToLowerInvariant() -replace '[^a-z0-9]', ''
        foreach ($part in $forbidden) {
            if ($normalized.Contains($part)) {
                throw "Prohibited evidence key at $Path.$($property.Name)"
            }
        }
        Assert-IdentityEvidenceRedacted `
            -Value $property.Value `
            -Path "$Path.$($property.Name)"
    }
}

function Export-IdentityEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')]
        [string]$RunId,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][object[]]$Records,
        [string[]]$ArtifactPaths = @()
    )

    $root = [IO.Path]::GetFullPath($OutputPath).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    $rootPrefix = $root + '\'
    $artifactDigests = [ordered]@{}
    foreach ($artifactPath in @($ArtifactPaths)) {
        $resolved = [IO.Path]::GetFullPath($artifactPath)
        if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Artifact path escapes output root: $resolved"
        }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "Artifact does not exist: $resolved"
        }
        $name = [IO.Path]::GetFileName($resolved)
        if ($artifactDigests.Contains($name)) {
            throw "Duplicate artifact name: $name"
        }
        $artifactDigests[$name] = Get-DmsaSha256 -Path $resolved
    }
    $documents = @()
    foreach ($record in @($Records)) {
        if ($record.BeforeDigest -notmatch '^[0-9a-f]{64}$' -or
            $record.AfterDigest -notmatch '^[0-9a-f]{64}$') {
            throw 'BeforeDigest and AfterDigest must be lowercase SHA-256 values.'
        }
        Assert-IdentityEvidenceRedacted -Value $record.Metadata
        $started = if ($record.PSObject.Properties['StartedUtc']) {
            [string]$record.StartedUtc
        } else {
            [DateTime]::UtcNow.ToString('o')
        }
        $ended = if ($record.PSObject.Properties['EndedUtc']) {
            [string]$record.EndedUtc
        } else {
            [DateTime]::UtcNow.ToString('o')
        }
        $document = [ordered]@{
            schema_version = 1
            run_id = $RunId
            case_id = [string]$record.CaseId
            invariant_ids = @($record.InvariantIds)
            adapter = 'windows-dmsa'
            evidence_class = 'windows-observation'
            outcome = [string]$record.Outcome
            reason = [string]$record.Reason
            before_digest = [string]$record.BeforeDigest
            after_digest = [string]$record.AfterDigest
            artifact_digests = $artifactDigests
            started_utc = $started
            ended_utc = $ended
            metadata = $record.Metadata
        }
        Assert-IdentityEvidenceRedacted -Value $document
        $documents += $document
    }
    $lines = @(
        $documents | ForEach-Object {
            $_ | ConvertTo-Json -Depth 16 -Compress
        }
    )
    $ledgerPath = Join-Path $root 'evidence.jsonl'
    $encoding = New-Object Text.UTF8Encoding($false)
    $text = if ($lines.Count -eq 0) { '' } else { ($lines -join "`n") + "`n" }
    [IO.File]::WriteAllText($ledgerPath, $text, $encoding)
    $ledgerDigest = Get-DmsaSha256 -Path $ledgerPath
    $manifestPath = Join-Path $root 'manifest.json'
    $manifest = [ordered]@{
        format_version = 1
        ledger = 'evidence.jsonl'
        ledger_sha256 = $ledgerDigest
        record_count = $documents.Count
    }
    [IO.File]::WriteAllText(
        $manifestPath,
        (($manifest | ConvertTo-Json -Depth 4) + "`n"),
        $encoding
    )
    [pscustomobject]@{
        Path = $manifestPath
        LedgerPath = $ledgerPath
        LedgerSha256 = $ledgerDigest
        RecordCount = $documents.Count
    }
}
