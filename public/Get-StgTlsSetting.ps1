function Get-StgTlsSetting {
    <#
    .SYNOPSIS
        Check, configure, and verify SSL/TLS registry keys for vulnerability 76759.

    .DESCRIPTION
        Check, configure, and verify SSL/TLS registry keys for vulnerability 76759.

        Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled. FIPS 140-2-approved TLS versions include TLS V1.1 or greater. NIST SP 800-52 specifies the preferred configurations for government systems.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76759
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [PSFComputer[]]$ComputerName,
        [PSCredential]$Credential,
        [switch]$EnableException
    )
    begin {
        . "$script:ModuleRoot\private\Set-Defaults.ps1"
        $sriptblock = {
            $notes = $null
            #TLS registry keys
            $regkeys0 = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
            )

            #SSL registry keys
            $regkeys1 = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 1.0\Server",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
            )

            #STIG required key name
            $SubKeyName = "DisabledByDefault"

            foreach ($key0 in $regkeys0) {
                $STIGValue0 = "0"

                #If key doesn"t exist, create key
                if (-not (Test-Path $key0)) {
                    New-Item $key0 -Force | Out-Null
                }

                #Create STIG required key property and set proper value
                if ((Get-ItemProperty $key0).DisabledByDefault -ne "0") {
                    New-ItemProperty $key0 -Name $SubKeyName -PropertyType DWORD -Value $STIGValue0 -ErrorAction SilentlyContinue -Force | Out-Null
                }

                #Get current key property values
                $keyValue0 = (Get-ItemProperty $key0).DisabledByDefault
                $ValueType0 = (Get-Item $key0).GetValueKind("DisabledByDefault")

                #Check compliance of each key according to STIG

                if ($ValueType0 -eq "DWORD") {
                    if ($keyValue0 -eq $STIGValue0) {
                        $compliant0 = $true
                    } else {
                        $compliant0 = $false
                    }
                } else {
                    $notes = "Incorrect Value Type"
                }

                [pscustomobject] @{
                    Id              = "V-76759"
                    ComputerName    = $env:COMPUTERNAME
                    Key             = $key0
                    KeyPropertyName = $SubKeyName
                    ValueType       = $ValueType0
                    KeyValue        = $keyValue0
                    STIGValue       = $STIGValue0
                    Compliant       = $compliant0
                    Notes           = $notes
                }
            }

            foreach ($key1 in $regkeys1) {
                $STIGValue1 = "1"
                #If key doesn"t exist, create key
                if (-not (Test-Path $key1)) {
                    New-Item $key1 -Force | Out-Null
                }

                #Create STIG required key property and set proper value
                if ((Get-ItemProperty $key1).DisabledByDefault -ne "1") {
                    New-ItemProperty $key1 -Name $SubKeyName -PropertyType DWORD -Value $STIGValue1 -ErrorAction SilentlyContinue -Force | Out-Null
                }

                #Get current key property values
                $keyValue1 = (Get-ItemProperty $key1).DisabledByDefault
                $ValueType1 = (Get-Item $key1).GetValueKind("DisabledByDefault")

                #Check compliance of each key according to STIG
                if ($ValueType1 -eq "DWORD") {
                    if ($keyValue1 -eq $STIGValue1) {
                        $compliant1 = $true
                    } else {
                        $compliant1 = $false
                    }
                } else {
                    $notes = "Incorrect Value Type"
                }

                [pscustomobject] @{
                    Id              = "V-76759"
                    ComputerName    = $env:COMPUTERNAME
                    Key             = $key1
                    KeyPropertyName = $SubKeyName
                    ValueType       = $ValueType1
                    KeyValue        = $keyValue1
                    StigValue       = $STIGValue1
                    Compliant       = $compliant1
                    Notes           = $notes
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Key, KeyPropertyName, ValueType, KeyValue, StigValue, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}