function Get-StgDoubleEscape {
<#
    .SYNOPSIS
        Configure and verify Allow Double Escaping settings for vulnerability 76825.

    .DESCRIPTION
        Configure and verify Allow Double Escaping settings for vulnerability 76825.

    .NOTES
        Tags: V-76825
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
        $filterpath = 'system.webServer/security/requestFiltering'



        foreach($webname in $webnames) {

            $PreConfigDoubleEscaping = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowDoubleEscaping

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name allowDoubleEscaping -Value "False"

            $PostConfigurationDoubleEscaping = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowDoubleEscaping

            [pscustomobject] @{
                Vulnerability = "V-76825"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigDoubleEscaping = $PreConfigDoubleEscaping.Value
                PostConfigurationDoubleEscaping = $PostConfigurationDoubleEscaping.Value
                Compliant = if ($PostConfigurationDoubleEscaping.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}