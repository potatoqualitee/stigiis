function Get-StgClientCertificate {
    <#
    .SYNOPSIS
        Get site SSL settings for vulnerability 76809, 76851, & 76861.

    .DESCRIPTION
        Get site SSL settings for vulnerability 76809, 76851, & 76861.

        Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. The web server must utilize approved encryption when receiving transmitted data.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76809, V-76851, V-76861
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT
        Caution: Setting Client Certificates to Required breaks SolarWinds.

    .EXAMPLE
        PS C:\> Get-StgClientCertificate -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgClientCertificate -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and reports the necessary information

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
        $scriptblock = {
            $webnames = (Get-Website).Name
            foreach ($webname in $webnames) {
                #Pre-configuration SSL values for sites
                $flags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                #Pre-configuration data results
                $preconfig = @(
                    if ($flags -eq "Ssl" ) {
                        "SSL: Required | Client Certificates: Ignore"
                    } elseif ($flags -eq "Ssl,SslNegotiateCert" ) {
                        "SSL: Required | Client Certificates: Accept"
                    } elseif ($flags -eq "Ssl,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($flags -eq "Ssl,Ssl128" ) {
                        "SSL: Required | Client Certificates: Ignore | SSL: 128"
                    } elseif ($flags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($flags -eq "Ssl,SslNegotiateCert,Ssl128" ) {
                        "SSL: Required | Client Certificates: Accept | SSL: 128"
                    } elseif ($flags -eq "Ssl,SslRequireCert,Ssl128" -or $flags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                        "SSL: Required | Client Certificates: Require | SSL: 128"
                    } elseif ($flags -eq "SslNegotiateCert" ) {
                        "SSL: Not Required | Client Certificates: Accept"
                    } elseif ($flags -eq "SslNegotiateCert,SslRequireCert" -or $flags -eq "SslRequireCert") {
                        "SSL: Not Required | Client Certificates: Require"
                    } elseif ($flags -eq "SslRequireCert,Ssl128") {
                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    } elseif ($flags -eq "SslNegotiateCert,Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                    } elseif ($flags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    } elseif ($flags -eq "Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                    } else {
                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )


                #Check SSL setting compliance
                if ($preconfig -eq "SSL: Required | Client Certificates: Require" -or $preconfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76861"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Value        = $flags
                    Compliant    = $compliant
                    Notes        = "Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Value, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
