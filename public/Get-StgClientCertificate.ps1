function Get-StgClientCertificate {
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


            foreach($webname in $webnames) {

                #Pre-configuration SSL values for sites
                $PreFlags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                if ($PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $PreFlags -ne "Ssl,SslNegotiateCert" -or $PreFlags -ne "Ssl,SslNegotiateCert,Ssl128" -or $PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                    #Set SSL requirements
                    Set-WebConfiguration -Location $webname -Filter "system.webserver/security/access" -Value "Ssl,SslNegotiateCert,Ssl128"
                }

                #Post-configuration SSL values
                $PostFlags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                #Pre-configuration data results
                $PreConfig = @(

                    if ($PreFlags -eq "Ssl" ) {

                        "SSL: Required | Client Certificates: Ignore"
                    }

                    elseif ($PreFlags -eq "Ssl,SslNegotiateCert" ) {

                        "SSL: Required | Client Certificates: Accept"
                    }

                    elseif ($PreFlags -eq "Ssl,SslRequireCert" ) {

                        "SSL: Required | Client Certificates: Require"
                    }

                    elseif ($PreFlags -eq "Ssl,Ssl128" ) {

                        "SSL: Required | Client Certificates: Ignore | SSL: 128"
                    }

                    elseif ($PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {

                        "SSL: Required | Client Certificates: Require"
                    }

                    elseif ($PreFlags -eq "Ssl,SslNegotiateCert,Ssl128" ) {

                        "SSL: Required | Client Certificates: Accept | SSL: 128"
                    }

                    elseif ($PreFlags -eq "Ssl,SslRequireCert,Ssl128" -or $PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                        "SSL: Required | Client Certificates: Require | SSL: 128"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert" ) {

                        "SSL: Not Required | Client Certificates: Accept"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert" -or $PreFlags -eq "SslRequireCert") {

                        "SSL: Not Required | Client Certificates: Require"
                    }

                    elseif ($PreFlags -eq "SslRequireCert,Ssl128") {

                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert,Ssl128" ) {

                        "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {

                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    }

                    elseif ($PreFlags -eq "Ssl128" ) {

                        "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                    }

                    else {

                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )

                #Post-configuration data results
                $PostConfig = @(

                    if ($PreFlags -eq "Ssl" ) {

                        "SSL: Required | Client Certificates: Ignore"
                    }

                    elseif ($PreFlags -eq "Ssl,SslNegotiateCert" ) {

                        "SSL: Required | Client Certificates: Accept"
                    }

                    elseif ($PreFlags -eq "Ssl,SslRequireCert" ) {

                        "SSL: Required | Client Certificates: Require"
                    }

                    elseif ($PreFlags -eq "Ssl,Ssl128" ) {

                        "SSL: Required | Client Certificates: Ignore | SSL: 128"
                    }

                    elseif ($PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {

                        "SSL: Required | Client Certificates: Require"
                    }

                    elseif ($PreFlags -eq "Ssl,SslNegotiateCert,Ssl128" ) {

                        "SSL: Required | Client Certificates: Accept | SSL: 128"
                    }

                    elseif ($PreFlags -eq "Ssl,SslRequireCert,Ssl128" -or $PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                        "SSL: Required | Client Certificates: Require | SSL: 128"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert" ) {

                        "SSL: Not Required | Client Certificates: Accept"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert" -or $PreFlags -eq "SslRequireCert") {

                        "SSL: Not Required | Client Certificates: Require"
                    }

                    elseif ($PreFlags -eq "SslRequireCert,Ssl128") {

                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert,Ssl128" ) {

                        "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                    }

                    elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {

                        "SSL: Not Required | Client Certificates: Require | SSL: 128"
                    }

                    elseif ($PreFlags -eq "Ssl128" ) {

                        "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                    }

                    else {

                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )

                #Check SSL setting compliance
                $Compliant = @(

                    if ($PostConfig -eq "SSL: Required | Client Certificates: Require" -or $PostConfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {

                        "Yes"
                    }

                    else {

                        "No: Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
                    }
                )

                [pscustomobject] @{

                    Vulnerability = "V-76861"
                    ComputerName = $env:ComputerName
                    SiteName = $webname
                    PreConfigFlags = "$PreConfig"
                    PostConfigurationFlags = "$PostConfig"
                    Compliant = "$Compliant"
                }
            }

            #Pre-configuration SSL values for server
            $PreFlags = Get-WebConfigurationProperty -Filter "system.webserver/security/access" -Name SSLFlags

            if ($PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $PreFlags -ne "Ssl,SslNegotiateCert" -or $PreFlags -ne "Ssl,SslNegotiateCert,Ssl128" -or $PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                #Set SSL requirements
                Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/access" -Name SSLFlags -Value "Ssl,SslNegotiateCert,Ssl128"
            }

            #Post-configuration SSL values
            $PostFlags = Get-WebConfigurationProperty -Filter "system.webserver/security/access" -Name SSLFlags

            #Pre-configuration data results
            $PreConfig = @(

                if ($PreFlags -eq "Ssl" ) {

                    "SSL: Required | Client Certificates: Ignore"
                }

                elseif ($PreFlags -eq "Ssl,SslNegotiateCert" ) {

                    "SSL: Required | Client Certificates: Accept"
                }

                elseif ($PreFlags -eq "Ssl,SslRequireCert" ) {

                    "SSL: Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq "Ssl,Ssl128" ) {

                    "SSL: Required | Client Certificates: Ignore | SSL: 128"
                }

                elseif ($PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {

                    "SSL: Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq "Ssl,SslNegotiateCert,Ssl128" ) {

                    "SSL: Required | Client Certificates: Accept | SSL: 128"
                }

                elseif ($PreFlags -eq "Ssl,SslRequireCert,Ssl128" -or $PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                    "SSL: Required | Client Certificates: Require | SSL: 128"
                }

                elseif ($PreFlags -eq "SslNegotiateCert" ) {

                    "SSL: Not Required | Client Certificates: Accept"
                }

                elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert" -or $PreFlags -eq "SslRequireCert") {

                    "SSL: Not Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq "SslRequireCert,Ssl128") {

                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                }

                elseif ($PreFlags -eq "SslNegotiateCert,Ssl128" ) {

                    "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                }

                elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {

                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                }

                elseif ($PreFlags -eq "Ssl128" ) {

                    "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                }

                else {

                    "SSL: Not Required | Client Certificates: Ignore"
                }
            )

            #Post-configuration data results
            $PostConfig = @(

                if ($PreFlags -eq "Ssl" ) {

                    "SSL: Required | Client Certificates: Ignore"
                }

                elseif ($PreFlags -eq "Ssl,SslNegotiateCert" ) {

                    "SSL: Required | Client Certificates: Accept"
                }

                elseif ($PreFlags -eq "Ssl,SslRequireCert" ) {

                    "SSL: Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq "Ssl,Ssl128" ) {

                    "SSL: Required | Client Certificates: Ignore | SSL: 128"
                }

                elseif ($PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {

                    "SSL: Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq "Ssl,SslNegotiateCert,Ssl128" ) {

                    "SSL: Required | Client Certificates: Accept | SSL: 128"
                }

                elseif ($PreFlags -eq "Ssl,SslRequireCert,Ssl128" -or $PreFlags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {

                    "SSL: Required | Client Certificates: Require | SSL: 128"
                }

                elseif ($PreFlags -eq "SslNegotiateCert" ) {

                    "SSL: Not Required | Client Certificates: Accept"
                }

                elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert" -or $PreFlags -eq "SslRequireCert") {

                    "SSL: Not Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq "SslRequireCert,Ssl128") {

                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                }

                elseif ($PreFlags -eq "SslNegotiateCert,Ssl128" ) {

                    "SSL: Not Required | Client Certificates: Accept | SSL: 128"
                }

                elseif ($PreFlags -eq "SslNegotiateCert,SslRequireCert,Ssl128" ) {

                    "SSL: Not Required | Client Certificates: Require | SSL: 128"
                }

                elseif ($PreFlags -eq "Ssl128" ) {

                    "SSL: Not Required | Client Certificates: Ignore | SSL: 128"
                }

                else {

                    "SSL: Not Required | Client Certificates: Ignore"
                }
            )

            #Check SSL setting compliance
            $Compliant = @(

                if ($PostConfig -eq "SSL: Required | Client Certificates: Require" -or $PostConfig -eq "SSL: Required | Client Certificates: Require | SSL: 128") {

                    "Yes"
                }

                else {

                    "No: Configuring the Client Certificates settings to Require breaks SolarWinds Web GUI"
                }
            )

            [pscustomobject] @{

                Vulnerability = "V-76809, V-76851"
                ComputerName = $env:ComputerName
                SiteName = $env:ComputerName
                PreConfigFlags = "$PreConfig"
                PostConfigurationFlags = "$PostConfig"
                Compliant = "$Compliant"
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property ComputerName, Id, Sitename, Hostname, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}