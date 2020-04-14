function Set-StgClientCertificate {
    <#
    .SYNOPSIS
        Check, configure, and verify site SSL settings for vulnerability 76809, 76851, & 76861.

    .DESCRIPTION
        Check, configure, and verify site SSL settings for vulnerability 76809, 76851, & 76861.

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
        PS C:\> Set-StgClientCertificate -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgClientCertificate -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and updates the necessary setting

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
                $preflags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                if ($preflags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $preflags -ne "Ssl,SslNegotiateCert" -or $preflags -ne "Ssl,SslNegotiateCert,Ssl128" -or $preflags -ne "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                    #Set SSL requirements
                    Set-WebConfiguration -Location $webname -Filter "system.webserver/security/access" -Value "Ssl,SslNegotiateCert,Ssl128"
                }

                #Post-configuration SSL values
                $postflags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                #Pre-configuration data results
                $preconfig = @(
                    if ($preflags -eq "Ssl" ) {
                        "SSL: Required | Client Certificates: Ignore"
                    } elseif ($preflags -eq "Ssl,SslNegotiateCert" ) {
                        "SSL: Required | Client Certificates: Accept"
                    } elseif ($preflags -eq "Ssl,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($preflags -eq "Ssl,Ssl128" ) {
                        "SSL: Required | Client Certificates: Ignore | SSL: 128"
                    } elseif ($preflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($preflags -eq "Ssl,SslNegotiateCert,Ssl128" ) {
                        "SSL: Required | Client Certificates: Accept | SSL: 128"
                    } elseif ($preflags -eq "Ssl,SslRequireCert,Ssl128" -or $preflags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                        "SSL: Required | Client Certificates: Require | SSL: 128"
                    } elseif ($preflags -eq "SslNegotiateCert" ) {
                        "SSL: Not Required | Client Certificates: Accept"
                    } elseif ($preflags -eq "SslNegotiateCert,SslRequireCert" -or $preflags -eq "SslRequireCert") {
                        "SSL: Not Required | Client Certificates: Require"
                    } elseif ($preflags -eq "SslRequireCert,Ssl128") {
                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    } elseif ($preflags -eq "SslNegotiateCert,Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                    } elseif ($preflags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    } elseif ($preflags -eq "Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                    } else {
                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )

                #Post-configuration data results
                $postconfig = @(
                    if ($postflags -eq "Ssl" ) {
                        "SSL: Required | Client Certificates: Ignore"
                    } elseif ($postflags -eq "Ssl,SslNegotiateCert" ) {
                        "SSL: Required | Client Certificates: Accept"
                    } elseif ($postflags -eq "Ssl,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($postflags -eq "Ssl,Ssl128" ) {
                        "SSL: Required | Client Certificates: Ignore | SSL: 128"
                    } elseif ($postflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($postflags -eq "Ssl,SslNegotiateCert,Ssl128" ) {
                        "SSL: Required | Client Certificates: Accept | SSL: 128"
                    } elseif ($postflags -eq "Ssl,SslRequireCert,Ssl128" -or $postflags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                        "SSL: Required | Client Certificates: Require | SSL: 128"
                    } elseif ($postflags -eq "SslNegotiateCert" ) {
                        "SSL: Not Required | Client Certificates: Accept"
                    } elseif ($postflags -eq "SslNegotiateCert,SslRequireCert" -or $postflags -eq "SslRequireCert") {
                        "SSL: Not Required | Client Certificates: Require"
                    } elseif ($postflags -eq "SslRequireCert,Ssl128") {
                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    } elseif ($postflags -eq "SslNegotiateCert,Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                    } elseif ($postflags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    } elseif ($postflags -eq "Ssl128" ) {
                        "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                    } else {
                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )

                #Check SSL setting compliance
                $compliant = @(
                    if ($postconfig -eq "SSL: Required | Client Certificates: Require" -or $postconfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {
                        $true
                    } else {
                        $false
                    }
                )

                [pscustomobject] @{
                    Id           = "V-76861"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Before       = $preconfig
                    After        = $postconfig
                    Compliant    = $compliant
                    Notes        = "Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
                }
            }

            #Pre-configuration SSL values for server
            $preflags = Get-WebConfigurationProperty -Filter "system.webserver/security/access" -Name SSLFlags

            if ($preflags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $preflags -ne "Ssl,SslNegotiateCert" -or $preflags -ne "Ssl,SslNegotiateCert,Ssl128" -or $preflags -ne "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                #Set SSL requirements
                $null = Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/access" -Name SSLFlags -Value "Ssl,SslNegotiateCert,Ssl128"
            }

            #Post-configuration SSL values
            $postflags = Get-WebConfigurationProperty -Filter "system.webserver/security/access" -Name SSLFlags

            #Pre-configuration data results
            # should be a switch but it's already written >_<
            $preconfig = @(
                if ($preflags -eq "Ssl" ) {
                    "SSL: Required | Client Certificates: Ignore"
                } elseif ($preflags -eq "Ssl,SslNegotiateCert" ) {
                    "SSL: Required | Client Certificates: Accept"
                } elseif ($preflags -eq "Ssl,SslRequireCert" ) {
                    "SSL: Required | Client Certificates: Require"
                } elseif ($preflags -eq "Ssl,Ssl128" ) {
                    "SSL: Required | Client Certificates: Ignore | SSL: 128"
                } elseif ($preflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                    "SSL: Required | Client Certificates: Require"
                } elseif ($preflags -eq "Ssl,SslNegotiateCert,Ssl128" ) {
                    "SSL: Required | Client Certificates: Accept | SSL: 128"
                } elseif ($preflags -eq "Ssl,SslRequireCert,Ssl128" -or $preflags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                    "SSL: Required | Client Certificates: Require | SSL: 128"
                } elseif ($preflags -eq "SslNegotiateCert" ) {
                    "SSL: Not Required | Client Certificates: Accept"
                } elseif ($preflags -eq "SslNegotiateCert,SslRequireCert" -or $preflags -eq "SslRequireCert") {
                    "SSL: Not Required | Client Certificates: Require"
                } elseif ($preflags -eq "SslRequireCert,Ssl128") {
                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                } elseif ($preflags -eq "SslNegotiateCert,Ssl128" ) {
                    "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                } elseif ($preflags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {
                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                } elseif ($preflags -eq "Ssl128" ) {
                    "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                } else {
                    "SSL: Not Required | Client Certificates: Ignore"
                }
            )

            # Post-configuration data results
            # should be a switch but it's already written >_<
            $postconfig = @(
                if ($postflags -eq "Ssl" ) {
                    "SSL: Required | Client Certificates: Ignore"
                } elseif ($postflags -eq "Ssl,SslNegotiateCert" ) {
                    "SSL: Required | Client Certificates: Accept"
                } elseif ($postflags -eq "Ssl,SslRequireCert" ) {
                    "SSL: Required | Client Certificates: Require"
                } elseif ($postflags -eq "Ssl,Ssl128" ) {
                    "SSL: Required | Client Certificates: Ignore | SSL: 128"
                } elseif ($postflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                    "SSL: Required | Client Certificates: Require"
                } elseif ($postflags -eq "Ssl,SslNegotiateCert,Ssl128" ) {
                    "SSL: Required | Client Certificates: Accept | SSL: 128"
                } elseif ($postflags -eq "Ssl,SslRequireCert,Ssl128" -or $postflags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {
                    "SSL: Required | Client Certificates: Require | SSL: 128"
                } elseif ($postflags -eq "SslNegotiateCert" ) {
                    "SSL: Not Required | Client Certificates: Accept"
                } elseif ($postflags -eq "SslNegotiateCert,SslRequireCert" -or $postflags -eq "SslRequireCert") {
                    "SSL: Not Required | Client Certificates: Require"
                } elseif ($postflags -eq "SslRequireCert,Ssl128") {
                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                } elseif ($postflags -eq "SslNegotiateCert,Ssl128" ) {
                    "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                } elseif ($postflags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {
                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                } elseif ($postflags -eq "Ssl128" ) {
                    "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                } else {
                    "SSL: Not Required | Client Certificates: Ignore"
                }
            )

            #Check SSL setting compliance
            if ($postconfig -eq "SSL: Required | Client Certificates: Require" -or $postconfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id           = "V-76809", "V-76851"
                ComputerName = $env:COMPUTERNAME
                SiteName     = $env:COMPUTERNAME
                Before       = $preconfig
                After        = $postconfig
                Compliant    = $compliant
                Notes        = "Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Before, After, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

