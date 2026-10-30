$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $labRoot 'Invoke-PacObservation.ps1')

Describe 'Windows PAC observation contract' {
    It 'pins exact lab realm principal service and KDC identities' {
        $plan = Get-PacObservationPlan

        $plan.Realm | Should Be 'IDLAB.TEST'
        $plan.Principal | Should Be 'pac-client@IDLAB.TEST'
        $plan.Service | Should Be 'HTTP/pac-service.idlab.test'
        $plan.ClientSamAccountName | Should Be 'pac-client'
        $plan.ServiceSamAccountName | Should Be 'pac-service'
        $plan.TransientRoot | Should Be 'C:\IdentityLab\PAC'
        $plan.CaptureInterface | Should Be 'Ethernet'
        $plan.TicketTool | Should Be (Join-Path $env:SystemRoot 'System32\klist.exe')
        ($plan.Kdcs.Role -join ',') | Should Be 'rwdc,rodc'
        (($plan.Kdcs | ForEach-Object { $_.Address }) -join ',') |
            Should Be '172.28.30.10,172.28.30.11'
    }

    It 'keeps the RODC identifier separate while composing the KDC key version' {
        $composite = Join-PacRodcKeyVersion -RodcIdentifier 4543 -KeyVersion 1

        $composite | Should Be 297730049
        ($composite -shr 16) | Should Be 4543
        ($composite -band 0xffff) | Should Be 1
    }

    It 'rejects zero and out-of-range RODC key-version components' {
        { Join-PacRodcKeyVersion -RodcIdentifier 0 -KeyVersion 1 } | Should Throw
        { Join-PacRodcKeyVersion -RodcIdentifier 4543 -KeyVersion 0 } | Should Throw
        { Join-PacRodcKeyVersion -RodcIdentifier 65536 -KeyVersion 1 } | Should Throw
    }

    It 'classifies only the two exact lab KDC addresses' {
        (Resolve-PacKdcRole -Address '172.28.30.10') | Should Be 'rwdc'
        (Resolve-PacKdcRole -Address '172.28.30.11') | Should Be 'rodc'
        (Resolve-PacKdcRole -Address '172.28.30.20') | Should Be 'unknown'
    }

    It 'parses normalized cache metadata without retaining ticket bytes' {
        $text = @'
Cached Tickets: (1)

#0>     Client: pac-client @ IDLAB.TEST
        Server: HTTP/pac-service.idlab.test @ IDLAB.TEST
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 10/30/2026 10:00:00 (local)
        End Time:   10/30/2026 20:00:00 (local)
        Renew Time: 11/6/2026 10:00:00 (local)
        Kdc Called: ID-DC01.idlab.test
'@

        $result = @(ConvertFrom-PacKlistOutput -Text $text)

        $result.Count | Should Be 1
        $result[0].Client | Should Be 'pac-client@IDLAB.TEST'
        $result[0].Server | Should Be 'HTTP/pac-service.idlab.test@IDLAB.TEST'
        $result[0].EncryptionType | Should Be 'AES-256-CTS-HMAC-SHA1-96'
        $result[0].KdcCalled | Should Be 'ID-DC01.idlab.test'
        ($result[0].PSObject.Properties.Name -contains 'EncodedTicket') | Should Be $false
    }

    It 'accepts cache entries that omit the informational KDC field' {
        $text = @'
Cached Tickets: (1)

#0>     Client: pac-client @ IDLAB.TEST
        Server: krbtgt/IDLAB.TEST @ IDLAB.TEST
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
'@

        $result = @(ConvertFrom-PacKlistOutput -Text $text)

        $result.Count | Should Be 1
        $result[0].Server | Should Be 'krbtgt/IDLAB.TEST@IDLAB.TEST'
        $result[0].KdcCalled | Should Be $null
    }

    It 'parses native CRLF klist records' {
        $text = "Cached Tickets: (1)`r`n`r`n#0>" +
            "`tClient: pac-client @ IDLAB.TEST`r`n" +
            "`tServer: HTTP/pac-service.idlab.test @ IDLAB.TEST`r`n" +
            "`tKerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96`r`n" +
            "`tKdc Called: ID-DC01.idlab.test`r`n"

        $result = @(ConvertFrom-PacKlistOutput -Text $text)

        $result.Count | Should Be 1
        $result[0].KdcCalled | Should Be 'ID-DC01.idlab.test'
    }

    It 'rejects raw ticket and PAC fields from evidence documents' {
        $message = $null
        try {
            Assert-PacEvidenceRedacted -Value ([ordered]@{
                case_id = 'pac-requestor-matches-cname'
                raw_pac_hex = '00'
            })
        } catch {
            $message = $_.Exception.Message
            $Error.Clear()
        }

        $message | Should Match 'Prohibited PAC evidence key'
    }

    It 'selects one exact type-128 PAC region from paired authdata fields' {
        $pac = Select-PacAuthenticationData `
            -Types @('1', '128', '141') `
            -Values @('aa', '00:11:22:33', 'bb')

        $pac | Should Be '00112233'
    }

    It 'rejects ambiguous or unpaired PAC authdata fields' {
        {
            Select-PacAuthenticationData `
                -Types @('128', '128') `
                -Values @('00', '11')
        } | Should Throw
        {
            Select-PacAuthenticationData `
                -Types @('1', '128') `
                -Values @('00')
        } | Should Throw
    }
}
