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
        $WebNames = (Get-Website).Name
        $FilterPath = 'system.webServer/directoryBrowse'
        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        foreach($WebName in $Webnames) {

            $PreDirectoryBrowsing = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled

            Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Enabled -Value "False"

            $PostDirectoryBrowsing = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled

            [pscustomobject] @{
                Vulnerability = "V-76829"
                Computername = $env:COMPUTERNAME
                SiteName = $WebName
                PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
                PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
                Compliant = if ($PostDirectoryBrowsing.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }

        $PreDirectoryBrowsing = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $FilterPath -Name Enabled

        Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name Enabled -Value "False"

        $PostDirectoryBrowsing = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $FilterPath -Name Enabled

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