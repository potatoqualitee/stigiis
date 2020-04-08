function Get-StgDirectoryBrowsing {
<#
.SYNOPSIS
    Configure and verify Directory Browsing properties for vulnerability 76733 & 76829.

.DESCRIPTION
    Configure and verify Directory Browsing properties for vulnerability 76733 & 76829.

    .NOTES
        Tags: V-76733, V-76829
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
        $filterpath = 'system.webServer/directoryBrowse'


        foreach($webname in $webnames) {

            $PreDirectoryBrowsing = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled

            Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled -Value "False"

            $PostDirectoryBrowsing = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled

            [pscustomobject] @{
                Vulnerability = "V-76829"
                Computername = $env:COMPUTERNAME
                SiteName = $webname
                PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
                PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
                Compliant = if ($PostDirectoryBrowsing.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }

        $PreDirectoryBrowsing = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $filterpath -Name Enabled

        Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled -Value "False"

        $PostDirectoryBrowsing = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $filterpath -Name Enabled

        [pscustomobject] @{
            Vulnerability = "V-76733"
            Computername = $env:COMPUTERNAME
            SiteName = $env:COMPUTERNAME
            PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
            PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
            Compliant = if ($PostDirectoryBrowsing.Value -eq $false) {
                "Yes"
            } else {
                "No"
            }
        }
    }
}