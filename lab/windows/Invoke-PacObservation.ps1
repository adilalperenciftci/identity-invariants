Set-StrictMode -Version Latest

function Get-PacObservationPlan {
    [CmdletBinding()]
    param()

    [pscustomobject][ordered]@{
        FormatVersion = 1
        Realm = 'IDLAB.TEST'
        Principal = 'pac-client@IDLAB.TEST'
        Service = 'HTTP/pac-service.idlab.test'
        ClientSamAccountName = 'pac-client'
        ServiceSamAccountName = 'pac-service'
        TransientRoot = 'C:\IdentityLab\PAC'
        CaptureInterface = 'Ethernet'
        TicketTool = (Join-Path $env:SystemRoot 'System32\klist.exe')
        Kdcs = @(
            [pscustomobject][ordered]@{
                Role = 'rwdc'
                Host = 'ID-DC01.idlab.test'
                Address = '172.28.30.10'
            },
            [pscustomobject][ordered]@{
                Role = 'rodc'
                Host = 'ID-RODC01.idlab.test'
                Address = '172.28.30.11'
            }
        )
    }
}

function Join-PacRodcKeyVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$RodcIdentifier,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$KeyVersion
    )

    return ([uint32](([uint32]$RodcIdentifier -shl 16) -bor [uint32]$KeyVersion))
}

function Resolve-PacKdcRole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Address)

    switch ($Address) {
        '172.28.30.10' { return 'rwdc' }
        '172.28.30.11' { return 'rodc' }
        default { return 'unknown' }
    }
}

function Select-PacAuthenticationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Types,
        [Parameter(Mandatory)][string[]]$Values
    )

    if ($Types.Count -ne $Values.Count) {
        throw 'Kerberos authdata type and value counts do not match.'
    }
    $matches = @(
        for ($index = 0; $index -lt $Types.Count; $index++) {
            if ($Types[$index] -eq '128') {
                $index
            }
        }
    )
    if ($matches.Count -ne 1) {
        throw 'Exactly one PAC authdata type-128 value is required.'
    }
    $hex = $Values[$matches[0]].ToLowerInvariant() -replace '[:\s]', ''
    if ($hex.Length -eq 0 -or $hex.Length % 2 -ne 0 -or $hex -notmatch '^[0-9a-f]+$') {
        throw 'PAC authdata must be complete hexadecimal bytes.'
    }
    return $hex
}

function ConvertFrom-PacKlistOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    $tickets = @()
    $blocks = [regex]::Split($Text, '(?m)^#\d+>') | Select-Object -Skip 1
    foreach ($block in $blocks) {
        $client = [regex]::Match($block, '(?m)^\s*Client:\s*(?<value>[^\r\n]+)\r?$')
        $server = [regex]::Match($block, '(?m)^\s*Server:\s*(?<value>[^\r\n]+)\r?$')
        $encryption = [regex]::Match(
            $block,
            '(?m)^\s*KerbTicket Encryption Type:\s*(?<value>[^\r\n]+)\r?$'
        )
        $kdc = [regex]::Match($block, '(?m)^\s*Kdc Called:\s*(?<value>[^\r\n]+)\r?$')
        if (-not ($client.Success -and $server.Success -and $encryption.Success)) {
            throw (
                'klist ticket metadata is incomplete ' +
                "(client=$($client.Success), server=$($server.Success), " +
                "encryption=$($encryption.Success), kdc=$($kdc.Success))."
            )
        }
        $tickets += [pscustomobject][ordered]@{
            Client = ($client.Groups['value'].Value.Trim() -replace '\s*@\s*', '@')
            Server = ($server.Groups['value'].Value.Trim() -replace '\s*@\s*', '@')
            EncryptionType = $encryption.Groups['value'].Value.Trim()
            KdcCalled = if ($kdc.Success) { $kdc.Groups['value'].Value.Trim() } else { $null }
        }
    }
    return $tickets
}

function Assert-PacEvidenceRedacted {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $normalized = ([string]$key).ToLowerInvariant() -replace '[^a-z0-9]', ''
            if ($normalized -match '(rawpac|rawticket|encodedticket|keytab|password)') {
                throw "Prohibited PAC evidence key: $key"
            }
            Assert-PacEvidenceRedacted -Value $Value[$key]
        }
        return
    }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            $normalized = $property.Name.ToLowerInvariant() -replace '[^a-z0-9]', ''
            if ($normalized -match '(rawpac|rawticket|encodedticket|keytab|password)') {
                throw "Prohibited PAC evidence key: $($property.Name)"
            }
            Assert-PacEvidenceRedacted -Value $property.Value
        }
        return
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            Assert-PacEvidenceRedacted -Value $item
        }
    }
}

function New-PacLabSecret {
    [CmdletBinding()]
    param()

    $bytes = New-Object byte[] 24
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
        return ('Aa1!' + [Convert]::ToBase64String($bytes))
    } finally {
        $generator.Dispose()
    }
}

function Register-PacTicketRequestTasks {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ClientSecret)

    $plan = Get-PacObservationPlan
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    foreach ($kdc in $plan.Kdcs) {
        $childPath = "C:\Users\Public\pac-$($kdc.Role).json"
        $childScript = @"
`$ErrorActionPreference = 'Stop'
`$klist = '$($plan.TicketTool)'
& `$klist purge_bind | Out-Null
& `$klist purge | Out-Null
`$started = [DateTime]::UtcNow.ToString('o')
`$before = (& `$klist tickets | Out-String)
& `$klist add_bind '$($plan.Realm)' '$($kdc.Host)' | Out-Null
`$binding = (& `$klist query_bind | Out-String)
& `$klist get '$($plan.Service)' | Out-Null
if (`$LASTEXITCODE -ne 0) { throw 'Service ticket request failed.' }
`$after = (& `$klist tickets | Out-String)
`$ended = [DateTime]::UtcNow.ToString('o')
[ordered]@{
    started_utc = `$started
    ended_utc = `$ended
    before = `$before
    after = `$after
    binding = `$binding
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath '$childPath' -Encoding UTF8
"@
        $encoded = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($childScript)
        )
        $action = New-ScheduledTaskAction `
            -Execute $powershell `
            -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 1) `
            -MultipleInstances IgnoreNew
        Register-ScheduledTask `
            -TaskName "IdentityPac-$($kdc.Role)" `
            -Action $action `
            -Settings $settings `
            -User 'IDLAB\pac-client' `
            -Password $ClientSecret `
            -RunLevel Highest `
            -Force | Out-Null
    }
}

function Grant-PacBatchLogonRight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^S-1-5-(?:\d+-)+\d+$')]
        [string]$Sid
    )

    $plan = Get-PacObservationPlan
    $configuration = Join-Path $plan.TransientRoot 'user-rights.inf'
    $database = Join-Path $plan.TransientRoot 'user-rights.sdb'
    $log = Join-Path $plan.TransientRoot 'user-rights.log'
    foreach ($path in @($configuration, $database, $log)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    & (Join-Path $env:SystemRoot 'System32\secedit.exe') `
        /export /cfg $configuration /areas USER_RIGHTS /quiet
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $configuration)) {
        throw 'Local user-rights export failed.'
    }
    $lines = @(Get-Content -LiteralPath $configuration -Encoding Unicode)
    $entry = "*$Sid"
    $index = -1
    for ($position = 0; $position -lt $lines.Count; $position++) {
        if ($lines[$position] -match '^SeBatchLogonRight\s*=') {
            $index = $position
            break
        }
    }
    if ($index -ge 0) {
        $existing = @(
            ($lines[$index] -split '=', 2)[1] -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
        )
        if ($entry -notin $existing) {
            $lines[$index] = 'SeBatchLogonRight = ' + (($existing + $entry) -join ',')
        }
    } else {
        $lines += "SeBatchLogonRight = $entry"
    }
    Set-Content -LiteralPath $configuration -Value $lines -Encoding Unicode
    & (Join-Path $env:SystemRoot 'System32\secedit.exe') `
        /configure /db $database /cfg $configuration /areas USER_RIGHTS /log $log /quiet
    if ($LASTEXITCODE -ne 0) {
        throw 'Local batch-logon right reconciliation failed.'
    }
}

function Initialize-PacLabCaptureContext {
    [CmdletBinding()]
    param()

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'PAC capture context initialization is restricted to ID-SRV01.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $plan = Get-PacObservationPlan
    $server = 'ID-DC01.idlab.test'
    New-Item -ItemType Directory -Force -Path $plan.TransientRoot | Out-Null

    $clientSecret = New-PacLabSecret
    $clientSecure = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
    $client = Get-ADUser `
        -Filter "SamAccountName -eq '$($plan.ClientSamAccountName)'" `
        -Server $server `
        -ErrorAction Stop
    if ($null -eq $client) {
        New-ADUser `
            -Name $plan.ClientSamAccountName `
            -SamAccountName $plan.ClientSamAccountName `
            -UserPrincipalName $plan.Principal.ToLowerInvariant() `
            -AccountPassword $clientSecure `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -KerberosEncryptionType AES128,AES256 `
            -Server $server `
            -ErrorAction Stop
    } else {
        Set-ADAccountPassword `
            -Identity $client `
            -Reset `
            -NewPassword $clientSecure `
            -Server $server `
            -ErrorAction Stop
        Enable-ADAccount -Identity $client -Server $server -ErrorAction Stop
    }

    $serviceSecret = New-PacLabSecret
    $serviceSecure = ConvertTo-SecureString -String $serviceSecret -AsPlainText -Force
    $serviceSecret = $null
    $service = Get-ADUser `
        -Filter "SamAccountName -eq '$($plan.ServiceSamAccountName)'" `
        -Server $server `
        -ErrorAction Stop
    if ($null -eq $service) {
        New-ADUser `
            -Name $plan.ServiceSamAccountName `
            -SamAccountName $plan.ServiceSamAccountName `
            -UserPrincipalName 'pac-service@idlab.test' `
            -AccountPassword $serviceSecure `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -KerberosEncryptionType AES128,AES256 `
            -Server $server `
            -ErrorAction Stop
    } else {
        Set-ADAccountPassword `
            -Identity $service `
            -Reset `
            -NewPassword $serviceSecure `
            -Server $server `
            -ErrorAction Stop
        Enable-ADAccount -Identity $service -Server $server -ErrorAction Stop
    }

    $service = Get-ADUser `
        -Identity $plan.ServiceSamAccountName `
        -Properties ServicePrincipalName `
        -Server $server
    if ($plan.Service -notin @($service.ServicePrincipalName)) {
        Set-ADUser `
            -Identity $service `
            -Add @{ ServicePrincipalName = $plan.Service } `
            -Server $server `
            -ErrorAction Stop
    }

    $group = Get-ADGroup `
        -Filter "SamAccountName -eq 'pac-domain-local'" `
        -Server $server `
        -ErrorAction Stop
    if ($null -eq $group) {
        $group = New-ADGroup `
            -Name 'pac-domain-local' `
            -SamAccountName 'pac-domain-local' `
            -GroupScope DomainLocal `
            -GroupCategory Security `
            -PassThru `
            -Server $server `
            -ErrorAction Stop
    }
    $groupMembers = @(Get-ADGroupMember -Identity $group -Server $server)
    if ($plan.ClientSamAccountName -notin @($groupMembers.SamAccountName)) {
        Add-ADGroupMember `
            -Identity $group `
            -Members $plan.ClientSamAccountName `
            -Server $server `
            -ErrorAction Stop
    }

    $allowed = Get-ADGroup `
        -Identity 'Allowed RODC Password Replication Group' `
        -Server $server
    $allowedMembers = @(Get-ADGroupMember -Identity $allowed -Server $server)
    foreach ($name in @($plan.ClientSamAccountName, $plan.ServiceSamAccountName)) {
        if ($name -notin @($allowedMembers.SamAccountName)) {
            Add-ADGroupMember `
                -Identity $allowed `
                -Members $name `
                -Server $server `
                -ErrorAction Stop
        }
    }

    $client = Get-ADUser `
        -Identity $plan.ClientSamAccountName `
        -Properties SID `
        -Server $server
    $localAdministrators = @(
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    )
    if ($client.SID.Value -notin @($localAdministrators.SID.Value)) {
        Add-LocalGroupMember `
            -Group 'Administrators' `
            -Member "IDLAB\$($plan.ClientSamAccountName)" `
            -ErrorAction Stop
    }
    Grant-PacBatchLogonRight -Sid $client.SID.Value
    Register-PacTicketRequestTasks -ClientSecret $clientSecret
    $clientSecret = $null

    $keytabPath = Join-Path $plan.TransientRoot 'pac-service.keytab'
    if (Test-Path -LiteralPath $keytabPath) {
        Remove-Item -LiteralPath $keytabPath -Force
    }
    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = (Join-Path $env:SystemRoot 'System32\ktpass.exe')
    $processInfo.Arguments = @(
        "/out $keytabPath"
        "/princ $($plan.Service)@$($plan.Realm)"
        "/mapuser IDLAB\$($plan.ServiceSamAccountName)"
        '/mapop set'
        '/crypto AES256-SHA1'
        '/ptype KRB5_NT_PRINCIPAL'
        '+rndPass'
        '/minPass 32'
        '/maxPass 32'
    ) -join ' '
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $ktpass = New-Object Diagnostics.Process
    $ktpass.StartInfo = $processInfo
    [void]$ktpass.Start()
    [void]$ktpass.StandardOutput.ReadToEnd()
    [void]$ktpass.StandardError.ReadToEnd()
    $ktpass.WaitForExit()
    if ($ktpass.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $keytabPath)) {
        throw "ktpass failed with exit code $($ktpass.ExitCode)."
    }

    $client = Get-ADUser `
        -Identity $plan.ClientSamAccountName `
        -Properties SID `
        -Server $server
    $service = Get-ADUser `
        -Identity $plan.ServiceSamAccountName `
        -Properties msDS-KeyVersionNumber `
        -Server $server
    $rodcComputer = Get-ADComputer `
        -Identity 'ID-RODC01' `
        -Properties msDS-KrbTgtLink `
        -Server $server
    $rodcKrbTgt = Get-ADUser `
        -Identity $rodcComputer.'msDS-KrbTgtLink' `
        -Properties msDS-KeyVersionNumber,msDS-SecondaryKrbTgtNumber `
        -Server $server
    $rwdcKrbTgt = Get-ADUser `
        -Identity 'krbtgt' `
        -Properties msDS-KeyVersionNumber `
        -Server $server

    [pscustomobject][ordered]@{
        ClientSid = [string]$client.SID.Value
        ServiceKeyVersion = [int]$service.'msDS-KeyVersionNumber'
        KeytabPath = $keytabPath
        KeytabSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $keytabPath).
            Hash.ToLowerInvariant()
        RwdcKdcKeyVersion = [int]$rwdcKrbTgt.'msDS-KeyVersionNumber'
        RodcIdentifier = [int]$rodcKrbTgt.'msDS-SecondaryKrbTgtNumber'
        RodcKdcKeyVersion = Join-PacRodcKeyVersion `
            -RodcIdentifier $rodcKrbTgt.'msDS-SecondaryKrbTgtNumber' `
            -KeyVersion $rodcKrbTgt.'msDS-KeyVersionNumber'
    }
}

function Import-PacLabCaptureContext {
    [CmdletBinding()]
    param()

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'PAC capture context import is restricted to ID-SRV01.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $plan = Get-PacObservationPlan
    $server = 'ID-DC01.idlab.test'
    $keytabPath = Join-Path $plan.TransientRoot 'pac-service.keytab'
    foreach ($path in @($keytabPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "PAC capture context file is missing: $path"
        }
    }
    foreach ($role in @('rwdc', 'rodc')) {
        if (-not (Get-ScheduledTask -TaskName "IdentityPac-$role" -ErrorAction SilentlyContinue)) {
            throw "PAC ticket request task is missing for $role."
        }
    }
    $revealed = @(
        Get-ADDomainControllerPasswordReplicationPolicyUsage `
            -Identity 'ID-RODC01' `
            -RevealedAccounts `
            -Server $server
    )
    foreach ($name in @($plan.ClientSamAccountName, $plan.ServiceSamAccountName)) {
        if ($name -notin @($revealed.SamAccountName)) {
            throw "RODC password cache does not contain $name."
        }
    }
    $client = Get-ADUser `
        -Identity $plan.ClientSamAccountName `
        -Properties SID `
        -Server $server
    $service = Get-ADUser `
        -Identity $plan.ServiceSamAccountName `
        -Properties msDS-KeyVersionNumber `
        -Server $server
    $rodcComputer = Get-ADComputer `
        -Identity 'ID-RODC01' `
        -Properties msDS-KrbTgtLink `
        -Server $server
    $rodcKrbTgt = Get-ADUser `
        -Identity $rodcComputer.'msDS-KrbTgtLink' `
        -Properties msDS-KeyVersionNumber,msDS-SecondaryKrbTgtNumber `
        -Server $server
    $rwdcKrbTgt = Get-ADUser `
        -Identity 'krbtgt' `
        -Properties msDS-KeyVersionNumber `
        -Server $server

    [pscustomobject][ordered]@{
        ClientSid = [string]$client.SID.Value
        ServiceKeyVersion = [int]$service.'msDS-KeyVersionNumber'
        KeytabPath = $keytabPath
        KeytabSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $keytabPath).
            Hash.ToLowerInvariant()
        RwdcKdcKeyVersion = [int]$rwdcKrbTgt.'msDS-KeyVersionNumber'
        RodcIdentifier = [int]$rodcKrbTgt.'msDS-SecondaryKrbTgtNumber'
        RodcKdcKeyVersion = Join-PacRodcKeyVersion `
            -RodcIdentifier $rodcKrbTgt.'msDS-SecondaryKrbTgtNumber' `
            -KeyVersion $rodcKrbTgt.'msDS-KeyVersionNumber'
    }
}

function Invoke-PacTicketCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][ValidateSet('rwdc', 'rodc')][string]$KdcRole
    )

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'PAC ticket capture is restricted to ID-SRV01.'
    }
    $plan = Get-PacObservationPlan
    $kdc = $plan.Kdcs | Where-Object Role -eq $KdcRole
    $tshark = 'C:\Program Files\Wireshark\tshark.exe'
    $dumpcap = 'C:\Program Files\Wireshark\dumpcap.exe'
    foreach ($path in @($tshark, $dumpcap, $plan.TicketTool)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required PAC observation tool is missing: $path"
        }
    }
    $interfaceLine = & $tshark -D |
        Where-Object { $_ -match "\($([regex]::Escape($plan.CaptureInterface))\)$" }
    if (@($interfaceLine).Count -ne 1 -or $interfaceLine -notmatch '^(?<index>\d+)\.') {
        throw "Capture interface is not unique: $($plan.CaptureInterface)"
    }
    $interfaceIndex = $Matches['index']

    $pcapPath = Join-Path $plan.TransientRoot "$KdcRole.pcapng"
    $childPath = "C:\Users\Public\pac-$KdcRole.json"
    foreach ($path in @($pcapPath, $childPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    $captureInfo = New-Object Diagnostics.ProcessStartInfo
    $captureInfo.FileName = $dumpcap
    $captureInfo.Arguments = (
        "-i $interfaceIndex -f `"host $($kdc.Address) and port 88`" " +
        "-a duration:10 -w `"$pcapPath`" -q"
    )
    $captureInfo.UseShellExecute = $false
    $captureInfo.CreateNoWindow = $true
    $captureInfo.RedirectStandardOutput = $true
    $captureInfo.RedirectStandardError = $true
    $capture = New-Object Diagnostics.Process
    $capture.StartInfo = $captureInfo
    [void]$capture.Start()
    Start-Sleep -Seconds 1

    $taskName = "IdentityPac-$KdcRole"
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while (-not (Test-Path -LiteralPath $childPath) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    $task = Get-ScheduledTask -TaskName $taskName
    while ($task.State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
        $task = Get-ScheduledTask -TaskName $taskName
    }
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
    [void]$capture.StandardOutput.ReadToEnd()
    $captureError = $capture.StandardError.ReadToEnd()
    $capture.WaitForExit()
    if ($taskInfo.LastTaskResult -ne 0) {
        throw "Ticket request task failed with result $($taskInfo.LastTaskResult)."
    }
    if ($capture.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $pcapPath)) {
        throw "Packet capture failed with exit code $($capture.ExitCode): $captureError"
    }
    if (-not (Test-Path -LiteralPath $childPath)) {
        throw 'Ticket request metadata was not produced.'
    }

    $child = Get-Content -LiteralPath $childPath -Raw | ConvertFrom-Json
    try {
        $before = @(ConvertFrom-PacKlistOutput -Text $child.before)
        $after = @(ConvertFrom-PacKlistOutput -Text $child.after)
    } catch {
        $headings = @(
            (($child.before + [Environment]::NewLine + $child.after) -split '\r?\n') |
            Where-Object {
                $_ -match '^\s*(?:#\d+>|Client:|Server:|Kerb[^:]*:|Kdc[^:]*:)'
            } |
            ForEach-Object { $_.Trim() }
        )
        throw "klist metadata parse failed; observed headings: $($headings -join ' | ')"
    }
    $serviceCacheName = "$($plan.Service)@$($plan.Realm)"
    $beforeServers = @($before | ForEach-Object { $_.Server })
    $afterServers = @($after | ForEach-Object { $_.Server })
    if ($serviceCacheName -in $beforeServers) {
        throw 'Service ticket was present before the isolated request.'
    }
    if (@($afterServers | Where-Object { $_ -eq $serviceCacheName }).Count -ne 1) {
        throw 'Service ticket was not isolated after the request.'
    }
    if ($child.binding -notmatch [regex]::Escape($kdc.Host)) {
        throw "KDC binding did not name $($kdc.Host): $($child.binding.Trim())"
    }
    Remove-Item -LiteralPath $childPath -Force

    [pscustomobject][ordered]@{
        KdcRole = $KdcRole
        KdcHost = $kdc.Host
        KdcAddress = $kdc.Address
        StartedUtc = $child.started_utc
        EndedUtc = $child.ended_utc
        CacheBefore = $beforeServers
        CacheAfter = $afterServers
        CapturePath = $pcapPath
        CaptureSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $pcapPath).
            Hash.ToLowerInvariant()
    }
}

function ConvertTo-PacNormalizedEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Capture,
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$OutputPath
    )

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'PAC evidence normalization is restricted to ID-SRV01.'
    }
    $plan = Get-PacObservationPlan
    $tshark = 'C:\Program Files\Wireshark\tshark.exe'
    $python = (Get-Command python.exe -ErrorAction Stop).Source
    $filter = 'kerberos.msg_type == 13 && kerberos.pac.entries'
    $lines = @(
        & $tshark `
            -r $Capture.CapturePath `
            -o 'kerberos.decrypt:TRUE' `
            -o "kerberos.file:$($Context.KeytabPath)" `
            -Y $filter `
            -T fields `
            -E 'separator=/t' `
            -E 'occurrence=a' `
            -E 'aggregator=,' `
            -e frame.number `
            -e ip.src `
            -e ip.dst `
            -e kerberos.msg_type `
            -e kerberos.kvno `
            -e kerberos.ad_type `
            -e kerberos.ad_data |
        Where-Object { $_ }
    )
    if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1) {
        throw "Expected one decoded TGS-REP PAC frame, observed $($lines.Count)."
    }
    $fields = @($lines[0] -split "`t", 7)
    if ($fields.Count -ne 7) {
        throw 'Decoded TGS-REP field count is invalid.'
    }
    $frameNumber = 0
    $messageType = 0
    $ticketKeyVersion = 0
    if (-not [int]::TryParse($fields[0], [ref]$frameNumber) -or $frameNumber -lt 1) {
        throw 'Decoded TGS-REP frame number is invalid.'
    }
    if (-not [int]::TryParse($fields[3], [ref]$messageType) -or $messageType -ne 13) {
        throw 'Decoded Kerberos message is not a TGS-REP.'
    }
    if (
        -not [int]::TryParse($fields[4], [ref]$ticketKeyVersion) -or
        $ticketKeyVersion -ne $Context.ServiceKeyVersion
    ) {
        throw 'Decoded service-ticket key version does not match the directory.'
    }
    if ($fields[1] -ne $Capture.KdcAddress -or $fields[2] -ne '172.28.30.20') {
        throw 'Decoded TGS-REP source or destination does not match the bounded lab path.'
    }
    $authdataTypes = @($fields[5] -split ',')
    $authdataValues = @($fields[6] -split ',')
    $pacHex = Select-PacAuthenticationData `
        -Types $authdataTypes `
        -Values $authdataValues

    $issuedByRodc = $Capture.KdcRole -eq 'rodc'
    $kdcKeyVersion = if ($issuedByRodc) {
        $Context.RodcKdcKeyVersion
    } else {
        $Context.RwdcKdcKeyVersion
    }
    $expectedRodcIdentifier = if ($issuedByRodc) {
        $Context.RodcIdentifier
    } else {
        $null
    }
    $rawPath = Join-Path $plan.TransientRoot "raw-$($Capture.KdcRole).json"
    $document = [ordered]@{
        realm = $plan.Realm
        principal = $plan.Principal
        service = $plan.Service
        started_utc = $Capture.StartedUtc
        ended_utc = $Capture.EndedUtc
        cache_before = @($Capture.CacheBefore)
        cache_after = @($Capture.CacheAfter)
        requested_kdc = [ordered]@{
            host = $Capture.KdcHost
            address = $Capture.KdcAddress
            role = $Capture.KdcRole
        }
        observed_kdc = [ordered]@{
            host = $Capture.KdcHost
            address = $fields[1]
            role = $Capture.KdcRole
        }
        ticket_kvno = $ticketKeyVersion
        kdc_key_version = $kdcKeyVersion
        issued_by_rodc = $issuedByRodc
        expected_rodc_identifier = $expectedRodcIdentifier
        expected_requestor_sid = $Context.ClientSid
        frame_number = $frameNumber
        capture_sha256 = $Capture.CaptureSha256
        raw_pac_hex = $pacHex
    }
    $outputDirectory = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    $oldPythonPath = $env:PYTHONPATH
    try {
        $document |
            ConvertTo-Json -Depth 8 -Compress |
            Set-Content -LiteralPath $rawPath -Encoding UTF8
        $env:PYTHONPATH = Join-Path $RepositoryRoot 'src'
        $normalizerOutput = & $python `
            -m identity_invariants.adapters.windows_pac `
            $rawPath `
            $OutputPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "PAC normalizer failed: $($normalizerOutput -join ' ')"
        }
    } finally {
        $env:PYTHONPATH = $oldPythonPath
        if (Test-Path -LiteralPath $rawPath) {
            Remove-Item -LiteralPath $rawPath -Force
        }
        $pacHex = $null
    }
    $normalized = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
    Assert-PacEvidenceRedacted -Value $normalized
    if (
        $normalized.kdc.role -ne $Capture.KdcRole -or
        $normalized.kdc.address -ne $Capture.KdcAddress -or
        $normalized.packet.frame_number -ne $frameNumber -or
        $normalized.packet.capture_sha256 -ne $Capture.CaptureSha256
    ) {
        throw 'Normalized PAC evidence does not match the capture correlation fields.'
    }
    return $normalized
}

function Write-PacEvidenceLedger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Records,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    if ($Records.Count -ne 2) {
        throw 'PAC evidence ledger requires exactly two KDC records.'
    }
    $roles = @($Records | ForEach-Object { $_.kdc.role } | Sort-Object)
    if (($roles -join ',') -ne 'rodc,rwdc') {
        throw 'PAC evidence ledger requires one RWDC and one RODC record.'
    }
    foreach ($record in $Records) {
        Assert-PacEvidenceRedacted -Value $record
    }
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $ledgerPath = Join-Path $OutputDirectory 'evidence.jsonl'
    $ordered = @($Records | Sort-Object { $_.kdc.role })
    $lines = @($ordered | ForEach-Object { $_ | ConvertTo-Json -Depth 12 -Compress })
    [IO.File]::WriteAllLines($ledgerPath, $lines, (New-Object Text.UTF8Encoding($false)))
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $ledgerPath).
        Hash.ToLowerInvariant()
    $manifestPath = Join-Path $OutputDirectory 'evidence.jsonl.manifest.json'
    $manifest = [ordered]@{
        format_version = 1
        ledger = 'evidence.jsonl'
        ledger_sha256 = $digest
        record_count = $Records.Count
    }
    [IO.File]::WriteAllText(
        $manifestPath,
        (($manifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    [pscustomobject][ordered]@{
        LedgerPath = $ledgerPath
        ManifestPath = $manifestPath
        LedgerSha256 = $digest
        RecordCount = $Records.Count
    }
}

function Invoke-PacFinalObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    $context = Import-PacLabCaptureContext
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    foreach ($name in @(
        'normalized-rwdc.json',
        'normalized-rodc.json',
        'evidence.jsonl',
        'evidence.jsonl.manifest.json'
    )) {
        $path = Join-Path $OutputDirectory $name
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    $records = @()
    $summaries = @()
    foreach ($role in @('rwdc', 'rodc')) {
        $capture = Invoke-PacTicketCapture -Context $context -KdcRole $role
        $outputPath = Join-Path $OutputDirectory "normalized-$role.json"
        $record = ConvertTo-PacNormalizedEvidence `
            -Context $context `
            -Capture $capture `
            -RepositoryRoot $RepositoryRoot `
            -OutputPath $outputPath
        $records += $record
        $summaries += [pscustomobject][ordered]@{
            Role = $record.kdc.role
            Frame = $record.packet.frame_number
            Source = $record.kdc.address
            TicketKeyVersion = $record.ticket.key_version
            KdcKeyVersion = $record.kdc.key_version
            RodcIdentifier = $record.kdc.rodc_identifier
            PacSha256 = $record.packet.pac_sha256
            CaptureSha256 = $record.packet.capture_sha256
            BufferTypes = @($record.pac.buffer_types) -join ','
            SignatureRoles = @(
                $record.pac.signatures | ForEach-Object { $_.role }
            ) -join ','
            AttributesPresent = $record.pac.attributes_present
            RequestorPresent = $record.pac.requestor_present
            CacheIsolated = $record.cache_isolated
        }
    }
    $manifest = Write-PacEvidenceLedger `
        -Records $records `
        -OutputDirectory $OutputDirectory
    [pscustomobject][ordered]@{
        Summaries = $summaries
        LedgerPath = $manifest.LedgerPath
        ManifestPath = $manifest.ManifestPath
        LedgerSha256 = $manifest.LedgerSha256
        RecordCount = $manifest.RecordCount
        RawInputsRemoved = -not (
            (Test-Path -LiteralPath (Join-Path (Get-PacObservationPlan).TransientRoot 'raw-rwdc.json')) -or
            (Test-Path -LiteralPath (Join-Path (Get-PacObservationPlan).TransientRoot 'raw-rodc.json'))
        )
    }
}

function Remove-PacTransientMaterial {
    [CmdletBinding()]
    param()

    $plan = Get-PacObservationPlan
    foreach ($role in @('rwdc', 'rodc')) {
        $taskName = "IdentityPac-$role"
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }
    foreach ($path in @(
        (Join-Path $plan.TransientRoot 'pac-service.keytab'),
        (Join-Path $plan.TransientRoot 'rwdc.pcapng'),
        (Join-Path $plan.TransientRoot 'rodc.pcapng'),
        (Join-Path $plan.TransientRoot 'raw-rwdc.json'),
        (Join-Path $plan.TransientRoot 'raw-rodc.json'),
        (Join-Path $plan.TransientRoot 'user-rights.inf'),
        (Join-Path $plan.TransientRoot 'user-rights.sdb'),
        (Join-Path $plan.TransientRoot 'user-rights.log'),
        'C:\Users\Public\pac-rwdc.json',
        'C:\Users\Public\pac-rodc.json'
    )) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}
