function Get-StgSessionStateInProc {
<#
    .SYNOPSIS
    Configure and verify Session State Mode settings for vulnerability 76775 & 76813.

    .DESCRIPTION
    Configure and verify Session State Mode settings for vulnerability 76775 & 76813.

    Communication between a client and the web server is done using the HTTP protocol, but HTTP is a stateless protocol. In order to maintain a connection or session, a web server will generate a session identifier (ID) for each client session when the session is initiated. The session ID allows the web server to track a user session and, in many cases, the user, if the user previously logged into a hosted application. By being able to guess session IDs, an attacker can easily perform a man-in-the-middle attack. To truly generate random session identifiers that cannot be reproduced, the web server session ID generator, when used twice with the same input criteria, must generate an unrelated random ID. The session ID generator also needs to be a FIPS 140-2-approved generator.

    .NOTES
        Tags: V-76775, V-76813
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
        $webnames = (Get-Website).Name
        $filterpath = 'system.web/sessionState'



        $PreConfigMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode

        Set-WebConfigurationProperty -Filter $filterpath -Name Mode -Value "InProc"

        $PostConfigurationMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode

        [pscustomobject] @{
            Vulnerability = "V-76775"
            Computername = $env:COMPUTERNAME
            Sitename = $env:COMPUTERNAME
            PreConfigMode = $PreConfigMode
            PostConfigurationMode = $PostConfigurationMode
            Compliant = if ($PostConfigurationMode -eq "InProc") {
                "Yes"
            } else {
                "No"
            }
        }

        foreach($webname in $webnames) {
            $PreConfigMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode
            Set-WebConfigurationProperty -Filter $filterpath -Name Mode -Value "InProc"
            $PostConfigurationMode = Get-WebConfigurationProperty -Filter $filterpath -Name Mode

            [pscustomobject] @{
                Vulnerability = "V-76813"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigMode = $PreConfigMode
                PostConfigurationMode = $PostConfigurationMode
                Compliant = if ($PostConfigurationMode -eq "InProc") {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}