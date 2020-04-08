function Get-StgV-76737-76835 {
<#
    .SYNOPSIS
        Configure and verify HTTP Error Detail properties for vulnerability 76737 & 76835.

    .DESCRIPTION
        Configure and verify HTTP Error Detail properties for vulnerability 76737 & 76835.

        HTTP error pages contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of HTTP error pages with full information to remote requesters exposes internal configuration information to potential attackers.

    .NOTES
        Tags: V-76737, V-76835
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
        $filterpath = 'system.webServer/httpErrors'


        foreach($webname in $webnames) {
            $PreErrorMode = Get-WebConfigurationProperty -Filter $filterpath -Name ErrorMode
            Set-WebConfigurationProperty -Filter $filterpath -Name ErrorMode -Value "DetailedLocalOnly"
            $PostErrorMode = Get-WebConfigurationProperty -Filter $filterpath -Name ErrorMode
            [pscustomobject] @{
                Vulnerability = "V-76733, V-76835"
                Computername = $env:COMPUTERNAME
                SiteName = $webname
                PreConfigBrowsingEnabled = $PreErrorMode
                PostConfigurationBrowsingEnabled = $PostErrorMode
                Compliant = if ($PostErrorMode -eq "DetailedLocalOnly") {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}