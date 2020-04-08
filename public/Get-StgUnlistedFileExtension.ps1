function Get-StgUnlistedFileExtension {
<#
    .SYNOPSIS
        Configure and verify Allow Unlisted File Extensions settings for vulnerability 76827.

    .DESCRIPTION
        Configure and verify Allow Unlisted File Extensions settings for vulnerability 76827.

    .NOTES
        Commented out Set-ConfigurationProperty, this setting breaks the Web GUI for SolarWinds.

    .NOTES
        Tags: V-76827
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
        $filterpath = 'system.webServer/security/requestFiltering/fileExtensions'



        foreach($webname in $webnames) {

            $PreConfigUnlistedExtensions = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowUnlisted

            #Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name allowUnlisted -Value "False"

            $PostConfigurationUnlistedExtensions = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowUnlisted

            [pscustomobject] @{
                Vulnerability = "V-76827"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigUnlistedExtensions = $PreConfigUnlistedExtensions.Value
                PostConfigurationUnlistedExtensions = $PostConfigurationUnlistedExtensions.Value
                Compliant = if ($PostConfigurationUnlistedExtensions.Value -eq $false) {
                    "Yes"
                } else {
                    "No: Setting Allow Unlisted File Extensions to False breaks SolarWinds Web GUI"
                }
            }
        }
    }
}