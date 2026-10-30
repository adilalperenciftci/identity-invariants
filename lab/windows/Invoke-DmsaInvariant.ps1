Set-StrictMode -Version Latest

function Get-DmsaSha256 {
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Text')][string]$Text,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path
    )

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $stream = [IO.File]::OpenRead([IO.Path]::GetFullPath($Path))
            try {
                $bytes = $sha.ComputeHash($stream)
            } finally {
                $stream.Dispose()
            }
        } else {
            $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        }
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-DmsaLifecyclePlan {
    [CmdletBinding()]
    param()

    [pscustomobject][ordered]@{
        FormatVersion = 1
        DmsaContainer = 'CN=Managed Service Accounts,DC=idlab,DC=test'
        BuildDefaultState = 0
        DocumentedStandaloneState = 3
        Standalone = [pscustomobject]@{
            RequiredStates = @(0)
            TargetState = 3
        }
        Start = [pscustomobject]@{
            RequiredStates = @(0, 3)
            TargetState = 1
        }
        Complete = [pscustomobject]@{
            RequiredState = 1
            RequiredStates = @(1)
            TargetState = 2
        }
        Undo = [pscustomobject]@{
            RequiredState = 1
            RequiredStates = @(1)
            TargetState = 0
        }
        Reset = [pscustomobject]@{
            RequiredStates = @(1, 2, 3)
            TargetState = 0
        }
        Cases = @(
            [pscustomobject]@{
                CaseId = 'dmsa-reciprocal-migration-links'
                InvariantIds = @('DMSA-LINK-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-started-to-complete'
                InvariantIds = @('DMSA-STATE-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-temporary-rights-lifecycle'
                InvariantIds = @('DMSA-ACL-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-ordered-spn-transfer'
                InvariantIds = @('DMSA-SPN-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-enrolled-machine'
                InvariantIds = @('DMSA-MACHINE-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-rwdc-migration-write'
                InvariantIds = @('DMSA-RWDC-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-event-directory-correlation'
                InvariantIds = @('DMSA-EVENT-001')
            },
            [pscustomobject]@{
                CaseId = 'dmsa-reset-to-documented-state'
                InvariantIds = @('DMSA-ROLLBACK-001')
            }
        )
    }
}

function Test-DmsaTransition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(0, 3)][int]$CurrentState,
        [Parameter(Mandatory)]
        [ValidateSet('Standalone', 'Start', 'Complete', 'Undo', 'Reset')]
        [string]$Phase
    )

    $contract = (Get-DmsaLifecyclePlan).$Phase
    $allowed = $CurrentState -in @($contract.RequiredStates)
    [pscustomobject][ordered]@{
        Allowed = $allowed
        CurrentState = $CurrentState
        TargetState = $contract.TargetState
        Reason = if ($allowed) { 'accepted' } else { 'invalid_transition' }
    }
}

function Resolve-DmsaLegacyDistinguishedName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$LegacyAccount,
        [Parameter(Mandatory)][string]$Server
    )

    $matches = @(
        Get-ADUser `
            -Filter "SamAccountName -eq '$LegacyAccount'" `
            -Server $Server `
            -ErrorAction Stop
    )
    if ($matches.Count -ne 1) {
        throw "Legacy account must resolve to exactly one object: $LegacyAccount"
    }
    return [string]$matches[0].DistinguishedName
}

function ConvertTo-DmsaNormalizedValue {
    [CmdletBinding()]
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [byte[]]) {
        return [pscustomobject]@{
            Kind = 'binary-digest'
            Length = $Value.Length
            Sha256 = Get-DmsaSha256 -Text ([Convert]::ToBase64String($Value))
        }
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value.PSObject.Properties['DistinguishedName']) {
        return [string]$Value.DistinguishedName
    }
    if ($Value -is [Collections.IEnumerable]) {
        return @(
            $Value |
            ForEach-Object { ConvertTo-DmsaNormalizedValue -Value $_ } |
            Sort-Object { $_ | ConvertTo-Json -Depth 8 -Compress }
        )
    }
    return [string]$Value
}

function Get-DmsaRelevantAclEdges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$LegacyObject,
        [Parameter(Mandatory)]$DmsaObject,
        [Parameter(Mandatory)][string]$Server
    )

    $rolesBySid = @{
        ([string]$LegacyObject.SID.Value) = 'legacy'
        ([string]$DmsaObject.SID.Value) = 'dmsa'
    }
    $targets = @(
        [pscustomobject]@{
            Role = 'legacy'
            DistinguishedName = $LegacyObject.DistinguishedName
        },
        [pscustomobject]@{
            Role = 'dmsa'
            DistinguishedName = $DmsaObject.DistinguishedName
        }
    )
    $edges = @()
    foreach ($target in $targets) {
        $entry = New-Object DirectoryServices.DirectoryEntry(
            "LDAP://$Server/$($target.DistinguishedName)"
        )
        try {
            $rules = $entry.ObjectSecurity.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            )
            foreach ($rule in $rules) {
                $sid = [string]$rule.IdentityReference.Value
                if ($rolesBySid.ContainsKey($sid)) {
                    $edges += [pscustomobject][ordered]@{
                        TargetRole = $target.Role
                        TrusteeRole = $rolesBySid[$sid]
                        Rights = [string]$rule.ActiveDirectoryRights
                        AccessType = [string]$rule.AccessControlType
                        ObjectType = [string]$rule.ObjectType
                        InheritedObjectType = [string]$rule.InheritedObjectType
                        IsInherited = [bool]$rule.IsInherited
                    }
                }
            }
        } finally {
            $entry.Dispose()
        }
    }
    return @(
        $edges |
        Sort-Object TargetRole, TrusteeRole, Rights, ObjectType, InheritedObjectType
    )
}

function Get-DmsaGraphSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$LegacyAccount,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$DmsaAccount,
        [string]$Server = 'ID-DC01.idlab.test'
    )

    Import-Module ActiveDirectory -ErrorAction Stop
    $legacyProperties = @(
        'Enabled',
        'servicePrincipalName',
        'msDS-SupportedEncryptionTypes',
        'msDS-ManagedAccountPrecededByLinkBL',
        'msDS-SupersededManagedAccountLink',
        'msDS-SupersededServiceAccountState',
        'msDS-AllowedToDelegateTo',
        'msDS-AssignedAuthNPolicy',
        'userAccountControl'
    )
    $dmsaProperties = @(
        'Enabled',
        'servicePrincipalName',
        'msDS-SupportedEncryptionTypes',
        'msDS-DelegatedMSAState',
        'msDS-ManagedAccountPrecededByLink',
        'msDS-SupersededManagedAccountLinkBL',
        'msDS-AllowedToDelegateTo',
        'msDS-AssignedAuthNPolicy',
        'PrincipalsAllowedToRetrieveManagedPassword',
        'userAccountControl'
    )
    $legacy = Get-ADUser `
        -Filter "SamAccountName -eq '$LegacyAccount'" `
        -Server $Server `
        -Properties $legacyProperties `
        -ErrorAction SilentlyContinue
    $dmsa = Get-ADServiceAccount `
        -Filter "Name -eq '$DmsaAccount'" `
        -Server $Server `
        -Properties $dmsaProperties `
        -ErrorAction SilentlyContinue
    $aclEdges = if ($legacy -and $dmsa) {
        Get-DmsaRelevantAclEdges `
            -LegacyObject $legacy `
            -DmsaObject $dmsa `
            -Server $Server
    } else {
        @()
    }

    $legacyRecord = if ($legacy) {
        [pscustomobject][ordered]@{
            Exists = $true
            DistinguishedName = $legacy.DistinguishedName
            ObjectGuid = $legacy.ObjectGuid.Guid
            Enabled = [bool]$legacy.Enabled
            UserAccountControl = [int]$legacy.userAccountControl
            KerberosEncryptionTypes = [int]$legacy.'msDS-SupportedEncryptionTypes'
            ServicePrincipalNames = @($legacy.servicePrincipalName | Sort-Object)
            PrecededByBackLinks = @(
                $legacy.'msDS-ManagedAccountPrecededByLinkBL' | Sort-Object
            )
            SupersedingLinks = @(
                $legacy.'msDS-SupersededManagedAccountLink' | Sort-Object
            )
            SupersededState = if (
                $null -eq $legacy.'msDS-SupersededServiceAccountState'
            ) { 0 } else { [int]$legacy.'msDS-SupersededServiceAccountState' }
            DelegationTargets = @($legacy.'msDS-AllowedToDelegateTo' | Sort-Object)
            AuthenticationPolicy = ConvertTo-DmsaNormalizedValue `
                -Value $legacy.'msDS-AssignedAuthNPolicy'
        }
    } else {
        [pscustomobject][ordered]@{ Exists = $false }
    }
    $dmsaRecord = if ($dmsa) {
        $rawState = $dmsa.'msDS-DelegatedMSAState'
        [pscustomobject][ordered]@{
            Exists = $true
            DistinguishedName = $dmsa.DistinguishedName
            ObjectGuid = $dmsa.ObjectGuid.Guid
            Enabled = [bool]$dmsa.Enabled
            UserAccountControl = [int]$dmsa.userAccountControl
            State = if ($null -eq $rawState) { 0 } else { [int]$rawState }
            KerberosEncryptionTypes = [int]$dmsa.'msDS-SupportedEncryptionTypes'
            ServicePrincipalNames = @($dmsa.servicePrincipalName | Sort-Object)
            PredecessorLinks = @(
                $dmsa.'msDS-ManagedAccountPrecededByLink' | Sort-Object
            )
            SupersededBackLinks = @(
                $dmsa.'msDS-SupersededManagedAccountLinkBL' | Sort-Object
            )
            DelegationTargets = @($dmsa.'msDS-AllowedToDelegateTo' | Sort-Object)
            AuthenticationPolicy = ConvertTo-DmsaNormalizedValue `
                -Value $dmsa.'msDS-AssignedAuthNPolicy'
            EnrolledPrincipals = @(
                $dmsa.PrincipalsAllowedToRetrieveManagedPassword |
                ForEach-Object { ConvertTo-DmsaNormalizedValue -Value $_ } |
                Sort-Object
            )
        }
    } else {
        [pscustomobject][ordered]@{ Exists = $false; State = 0 }
    }
    $document = [pscustomobject][ordered]@{
        FormatVersion = 1
        Domain = 'idlab.test'
        Server = $Server
        Legacy = $legacyRecord
        Dmsa = $dmsaRecord
        AclEdges = @($aclEdges)
    }
    $canonical = $document | ConvertTo-Json -Depth 12 -Compress
    [pscustomobject][ordered]@{
        Digest = Get-DmsaSha256 -Text $canonical
        Document = $document
    }
}

function Initialize-DmsaLabBaseline {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][Security.SecureString]$LegacyAccountPassword,
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$LegacyAccount = 'svc-legacy',
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$DmsaAccount = 'svc-dmsa',
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$MemberComputer = 'ID-SRV01'
    )

    if ($env:COMPUTERNAME -ne 'ID-DC01') {
        throw 'dMSA baseline creation is restricted to ID-DC01.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $server = 'ID-DC01.idlab.test'
    $root = Get-ADRootDSE -Server $server -ErrorAction Stop
    if ($root.defaultNamingContext -ne 'DC=idlab,DC=test') {
        throw 'Unexpected default naming context.'
    }
    $base = 'OU=IdentityLab,DC=idlab,DC=test'
    if (-not (Get-ADOrganizationalUnit `
        -Filter "DistinguishedName -eq '$base'" `
        -Server $server `
        -ErrorAction SilentlyContinue
    )) {
        if ($PSCmdlet.ShouldProcess($base, 'Create identity lab OU')) {
            New-ADOrganizationalUnit `
                -Name 'IdentityLab' `
                -Path 'DC=idlab,DC=test' `
                -Server $server `
                -ProtectedFromAccidentalDeletion:$true `
                -ErrorAction Stop
        }
    }
    $legacy = Get-ADUser `
        -Filter "SamAccountName -eq '$LegacyAccount'" `
        -Server $server `
        -ErrorAction SilentlyContinue
    if (-not $legacy -and $PSCmdlet.ShouldProcess($LegacyAccount, 'Create AES-only lab service user')) {
        New-ADUser `
            -Name $LegacyAccount `
            -SamAccountName $LegacyAccount `
            -Path $base `
            -AccountPassword $LegacyAccountPassword `
            -Enabled:$true `
            -PasswordNeverExpires:$true `
            -KerberosEncryptionType AES128, AES256 `
            -ServicePrincipalNames @('HOST/legacy.idlab.test') `
            -Server $server `
            -ErrorAction Stop
    }
    $policy = Get-ADAuthenticationPolicy `
        -Filter "Name -eq 'IdentityLabServicePolicy'" `
        -Server $server `
        -ErrorAction Stop
    if (-not $policy) {
        if ($PSCmdlet.ShouldProcess(
            'IdentityLabServicePolicy',
            'Create non-enforced lab authentication policy'
        )) {
            $policy = New-ADAuthenticationPolicy `
                -Name 'IdentityLabServicePolicy' `
                -ServiceTGTLifetimeMins 60 `
                -ProtectedFromAccidentalDeletion:$false `
                -PassThru `
                -Server $server `
                -ErrorAction Stop
        }
    }
    $legacy = Get-ADUser `
        -Filter "SamAccountName -eq '$LegacyAccount'" `
        -Server $server `
        -Properties 'msDS-AllowedToDelegateTo', 'msDS-AssignedAuthNPolicy' `
        -ErrorAction Stop
    $delegationTarget = 'HOST/ID-SRV01.idlab.test'
    if ($delegationTarget -notin @($legacy.'msDS-AllowedToDelegateTo')) {
        if ($PSCmdlet.ShouldProcess($LegacyAccount, 'Add lab delegation target')) {
            Set-ADUser `
                -Identity $legacy `
                -Add @{ 'msDS-AllowedToDelegateTo' = $delegationTarget } `
                -Server $server `
                -ErrorAction Stop
        }
    }
    if ([string]$legacy.'msDS-AssignedAuthNPolicy' -ne $policy.DistinguishedName) {
        if ($PSCmdlet.ShouldProcess($LegacyAccount, 'Assign lab authentication policy')) {
            Set-ADUser `
                -Identity $legacy `
                -AuthenticationPolicy $policy `
                -Server $server `
                -ErrorAction Stop
        }
    }
    $member = Get-ADComputer `
        -Identity $MemberComputer `
        -Server $server `
        -ErrorAction Stop
    $dmsa = Get-ADServiceAccount `
        -Filter "Name -eq '$DmsaAccount'" `
        -Server $server `
        -ErrorAction SilentlyContinue
    if (-not $dmsa -and $PSCmdlet.ShouldProcess($DmsaAccount, 'Create delegated managed service account')) {
        New-ADServiceAccount `
            -Name $DmsaAccount `
            -DNSHostName "$DmsaAccount.idlab.test" `
            -CreateDelegatedServiceAccount `
            -KerberosEncryptionType AES128, AES256 `
            -PrincipalsAllowedToRetrieveManagedPassword $member `
            -Server $server `
            -ErrorAction Stop
    }
    Get-DmsaGraphSnapshot `
        -LegacyAccount $LegacyAccount `
        -DmsaAccount $DmsaAccount `
        -Server $server
}

function Get-DmsaAuditEventObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][DateTime]$StartTime
    )

    $logName = 'Microsoft-Windows-Kerberos/Operational'
    $events = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName = $logName
                Id = 307, 308, 309
                StartTime = $StartTime.ToLocalTime()
            } `
            -ErrorAction SilentlyContinue
    )
    $counts = [ordered]@{
        '307' = 0
        '308' = 0
        '309' = 0
    }
    foreach ($event in $events) {
        $key = [string][int]$event.Id
        if ($counts.Contains($key)) {
            $counts[$key]++
        }
    }
    $times = @(
        $events |
        Where-Object { $null -ne $_.TimeCreated } |
        ForEach-Object { $_.TimeCreated.ToUniversalTime() } |
        Sort-Object
    )
    [pscustomobject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        LogName = $logName
        EventIds = @(
            $events |
            ForEach-Object { [int]$_.Id } |
            Sort-Object -Unique
        )
        EventCounts = [pscustomobject]$counts
        RecordIds = @(
            $events |
            ForEach-Object { [long]$_.RecordId } |
            Sort-Object -Unique
        )
        Count = $events.Count
        FirstEventUtc = if ($times.Count) { $times[0].ToString('o') } else { $null }
        LastEventUtc = if ($times.Count) { $times[-1].ToString('o') } else { $null }
    }
}

function Merge-DmsaUserRightSid {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$ExistingValue,
        [Parameter(Mandatory)]
        [ValidatePattern('^S-1-5(?:-[0-9]+){2,}$')]
        [string]$AccountSid
    )

    $entries = @(
        $ExistingValue -split ',' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
    )
    $target = "*$AccountSid"
    $changed = $target -notin $entries
    if ($changed) {
        $entries += $target
    }
    [pscustomobject][ordered]@{
        Changed = $changed
        Value = $entries -join ','
        EntryCount = $entries.Count
    }
}

function Grant-DmsaServiceLogonRight {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^S-1-5(?:-[0-9]+){2,}$')]
        [string]$AccountSid
    )

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'Service-logon right assignment is restricted to ID-SRV01.'
    }
    $tempRoot = Join-Path $env:TEMP ("IdentityLab-UserRight-{0}" -f [guid]::NewGuid())
    $beforePath = Join-Path $tempRoot 'before.inf'
    $afterPath = Join-Path $tempRoot 'after.inf'
    $policyPath = Join-Path $tempRoot 'policy.inf'
    $databasePath = Join-Path $tempRoot 'policy.sdb'
    New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop | Out-Null
    try {
        & secedit.exe /export /cfg $beforePath /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Local user-right export failed with exit code $LASTEXITCODE."
        }
        $line = Get-Content -LiteralPath $beforePath -ErrorAction Stop |
            Where-Object { $_ -match '^SeServiceLogonRight\s*=' } |
            Select-Object -First 1
        $existingValue = if ($line -match '^SeServiceLogonRight\s*=\s*(.*)$') {
            $Matches[1].Trim()
        } else {
            ''
        }
        $merged = Merge-DmsaUserRightSid `
            -ExistingValue $existingValue `
            -AccountSid $AccountSid
        if ($merged.Changed -and $PSCmdlet.ShouldProcess(
            'ID-SRV01',
            'Grant the lab legacy account service-logon right'
        )) {
            $policy = @(
                '[Unicode]',
                'Unicode=yes',
                '[Version]',
                'signature="$CHICAGO$"',
                'Revision=1',
                '[Privilege Rights]',
                "SeServiceLogonRight = $($merged.Value)"
            )
            [IO.File]::WriteAllLines(
                $policyPath,
                $policy,
                [Text.Encoding]::Unicode
            )
            & secedit.exe `
                /configure `
                /db $databasePath `
                /cfg $policyPath `
                /areas USER_RIGHTS `
                /quiet | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Local user-right configuration failed with exit code $LASTEXITCODE."
            }
        }
        & secedit.exe /export /cfg $afterPath /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Local user-right verification failed with exit code $LASTEXITCODE."
        }
        $verifiedLine = Get-Content -LiteralPath $afterPath -ErrorAction Stop |
            Where-Object { $_ -match '^SeServiceLogonRight\s*=' } |
            Select-Object -First 1
        if ($verifiedLine -notmatch [regex]::Escape("*$AccountSid")) {
            throw 'Service-logon right verification did not find the lab account.'
        }
        [pscustomobject][ordered]@{
            ComputerName = $env:COMPUTERNAME
            AccountRole = 'legacy'
            Changed = $merged.Changed
            ExistingEntryCount = @($existingValue -split ',' | Where-Object { $_ }).Count
            ResultEntryCount = $merged.EntryCount
            RollbackByCheckpointRequired = $merged.Changed
        }
    } finally {
        $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
        $expectedPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\IdentityLab-UserRight-'
        if ($resolvedTemp.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Get-ChildItem -LiteralPath $resolvedTemp -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $resolvedTemp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-DmsaSystemKlistPath {
    [CmdletBinding()]
    param()

    $path = Join-Path $env:SystemRoot 'System32\klist.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Windows Kerberos tool is absent: $path"
    }
    return $path
}

function Invoke-DmsaMachineTicketRefresh {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'Machine-ticket refresh is restricted to ID-SRV01.'
    }
    if (-not $PSCmdlet.ShouldProcess(
        'ID-SRV01 local-system logon session',
        'Purge cached Kerberos tickets'
    )) {
        return [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Completed = $false
            ExitCode = $null
        }
    }
    $klist = Get-DmsaSystemKlistPath
    & $klist purge -li 0x3e7 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Machine-ticket refresh failed with exit code $exitCode."
    }
    [pscustomobject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        LogonSession = 'local-system'
        Completed = $true
        ExitCode = $exitCode
    }
}

function Invoke-DmsaServiceLogonObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.SecureString]$AccountPassword,
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$AccountName = 'svc-legacy',
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')]
        [string]$DomainName = 'IDLAB'
    )

    if ($env:COMPUTERNAME -ne 'ID-SRV01') {
        throw 'Service-logon observation is restricted to ID-SRV01.'
    }
    if (-not ('IdentityLab.NativeLogon' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace IdentityLab {
    public static class NativeLogon {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser(
            string userName,
            string domain,
            IntPtr password,
            int logonType,
            int logonProvider,
            out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
'@
    }

    $started = [DateTime]::UtcNow
    $passwordPointer = [IntPtr]::Zero
    $token = [IntPtr]::Zero
    $succeeded = $false
    $errorCode = 0
    try {
        $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            $AccountPassword
        )
        $succeeded = [IdentityLab.NativeLogon]::LogonUser(
            $AccountName,
            $DomainName,
            $passwordPointer,
            5,
            0,
            [ref]$token
        )
        if (-not $succeeded) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    } finally {
        if ($token -ne [IntPtr]::Zero) {
            [void][IdentityLab.NativeLogon]::CloseHandle($token)
        }
        if ($passwordPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
        }
    }
    [pscustomobject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        AccountRole = 'legacy'
        LogonType = 'service'
        Succeeded = $succeeded
        ErrorCode = $errorCode
        StartedUtc = $started.ToString('o')
        EndedUtc = ([DateTime]::UtcNow).ToString('o')
    }
}

function Invoke-DmsaInvariantCase {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)]
        [ValidateSet('Start', 'Complete', 'Undo', 'Reset')]
        [string]$Phase,
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$LegacyAccount = 'svc-legacy',
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
        [string]$DmsaAccount = 'svc-dmsa',
        [string]$Server = 'ID-DC01.idlab.test'
    )

    if ($env:COMPUTERNAME -ne 'ID-DC01') {
        throw 'dMSA mutation is restricted to ID-DC01.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $before = Get-DmsaGraphSnapshot `
        -LegacyAccount $LegacyAccount `
        -DmsaAccount $DmsaAccount `
        -Server $Server
    $state = [int]$before.Document.Dmsa.State
    $transition = Test-DmsaTransition -CurrentState $state -Phase $Phase
    $started = [DateTime]::UtcNow
    if (-not $transition.Allowed) {
        return [pscustomobject][ordered]@{
            CaseId = $CaseId
            Phase = $Phase
            Outcome = 'reject'
            Reason = $transition.Reason
            BeforeDigest = $before.Digest
            AfterDigest = $before.Digest
            Before = $before.Document
            After = $before.Document
            EventIds = @()
            StartedUtc = $started.ToString('o')
            EndedUtc = ([DateTime]::UtcNow).ToString('o')
            MutationAttempted = $false
        }
    }
    $legacyIdentity = Resolve-DmsaLegacyDistinguishedName `
        -LegacyAccount $LegacyAccount `
        -Server $Server
    if ($PSCmdlet.ShouldProcess($DmsaAccount, "$Phase dMSA lifecycle transition")) {
        switch ($Phase) {
            'Start' {
                Start-ADServiceAccountMigration `
                    -Identity $DmsaAccount `
                    -SupersededAccount $legacyIdentity `
                    -Server $Server `
                    -ErrorAction Stop
            }
            'Complete' {
                Complete-ADServiceAccountMigration `
                    -Identity $DmsaAccount `
                    -SupersededAccount $legacyIdentity `
                    -Server $Server `
                    -ErrorAction Stop
            }
            'Undo' {
                Undo-ADServiceAccountMigration `
                    -Identity $DmsaAccount `
                    -SupersededAccount $legacyIdentity `
                    -Server $Server `
                    -ErrorAction Stop
            }
            'Reset' {
                Reset-ADServiceAccountMigration `
                    -Identity $DmsaAccount `
                    -SupersededAccount $legacyIdentity `
                    -Server $Server `
                    -ErrorAction Stop
            }
        }
    }
    $after = Get-DmsaGraphSnapshot `
        -LegacyAccount $LegacyAccount `
        -DmsaAccount $DmsaAccount `
        -Server $Server
    $events = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName = 'Microsoft-Windows-Kerberos/Operational'
                Id = 307, 308, 309
                StartTime = $started.ToLocalTime()
            } `
            -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Id
    )
    [pscustomobject][ordered]@{
        CaseId = $CaseId
        Phase = $Phase
        Outcome = 'observe'
        Reason = 'accepted'
        BeforeDigest = $before.Digest
        AfterDigest = $after.Digest
        Before = $before.Document
        After = $after.Document
        EventIds = @($events | Sort-Object -Unique)
        StartedUtc = $started.ToString('o')
        EndedUtc = ([DateTime]::UtcNow).ToString('o')
        MutationAttempted = $true
    }
}
