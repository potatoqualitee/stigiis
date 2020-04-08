function Get-StgSSLSetting {
    <#
    .SYNOPSIS
        Check, configure, and verify site SSL settings for vulnerability 76679, 76779, & 76781.

    .DESCRIPTION
        Check, configure, and verify site SSL settings for vulnerability 76679, 76779, & 76781.

    .NOTES
        Tags: V-76679, V-76779, V-76781
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
    }
    process {


        foreach($Webname in $WebNames) {

            #Pre-configuration SSL values
            $PreFlags = Get-WebConfigurationProperty -Location $Webname -Filter 'system.webserver/security/access' -Name SSLFlags

            if ($PreFlags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $PreFlags -ne "Ssl,SslNegotiateCert") {

                #Set SSL requirements
                Set-WebConfiguration -Location $Webname -Filter 'system.webserver/security/access' -Value 'Ssl,SslNegotiateCert'
            }

            #Post-configuration SSL values
            $PostFlags = Get-WebConfigurationProperty -Location $Webname -Filter 'system.webserver/security/access' -Name SSLFlags

            #Pre-configuration data results
            $PreConfig = @(


                if ($PreFlags -eq 'Ssl' ) {

                    "SSL: Required | Client Certificates: Ignore"
                }

                elseif ($PreFlags -eq 'Ssl,SslNegotiateCert' ) {

                    "SSL: Required | Client Certificates: Accept"
                }

                elseif ($PreFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {

                    "SSL: Required | Client Certificates: Require"
                }

                elseif ($PreFlags -eq 'SslNegotiateCert' ) {

                    "SSL: Not Required | Client Certificates: Accept"
                }

                elseif ($PreFlags -eq 'SslNegotiateCert,SslRequireCert' ) {

                    "SSL: Not Required | Client Certificates: Require"
                }

                else {

                    "SSL: Not Required | Client Certificates: Ignore"
                }
            )

            #Post-configuration data results
            $PostConfig = @(


                if ($PostFlags -eq 'Ssl' ) {

                    "SSL: Required | Client Certificates: Ignore"
                }

                elseif ($PostFlags -eq 'Ssl,SslNegotiateCert' ) {

                    "SSL: Required | Client Certificates: Accept"
                }

                elseif ($PostFlags -eq 'Ssl,SslNegotiateCert,SslRequireCert' ) {

                    "SSL: Required | Client Certificates: Require"
                }

                elseif ($PostFlags -eq 'SslNegotiateCert' ) {

                    "SSL: Not Required | Client Certificates: Accept"
                }

                elseif ($PostFlags -eq 'SslNegotiateCert,SslRequireCert' ) {

                    "SSL: Not Required | Client Certificates: Require"
                }

                else {

                    "SSL: Not Required | Client Certificates: Ignore"
                }
            )

            #Check SSL setting compliance
            $Compliant = @(

                if ($PostConfig -eq "SSL: Required | Client Certificates: Accept") {

                    "Yes"
                }

                elseif ($PostConfig -eq "SSL: Required | Client Certificates: Require") {

                    "Yes"
                }

                else {

                    "No"
                }
            )

            [pscustomobject] @{

                Vulnerability = "V-76679, V-76779, V-76781"
                SiteName = $Webname
                PreConfigFlags = "$PreConfig"
                PostConfigurationFlags = "$PostConfig"
                Compliant = "$Compliant"
            }
        }
    }
}