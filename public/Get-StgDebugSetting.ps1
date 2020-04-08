function Get-StgDebugSetting {
<#
.SYNOPSIS
    Configure and verify Debug Behavior settings for vulnerability 76837.

.DESCRIPTION
    Configure and verify Debug Behavior settings for vulnerability 76837.

    .NOTES
        Tags: V-76837
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
        $filterpath = 'system.web/compilation'
        foreach($webname in $webnames) {

            $PreConfigDebugBehavior = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Debug

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name Debug -Value "False"

            $PostConfigurationDebugBehavior = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Debug

            [pscustomobject] @{
                Vulnerability = "V-76837"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigDebugBehaviors = $PreConfigDebugBehavior.Value
                PostConfigurationDebugBehavior = $PostConfigurationDebugBehavior.Value
                Compliant = if ($PostConfigurationDebugBehavior.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}