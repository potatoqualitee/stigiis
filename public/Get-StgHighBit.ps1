function Get-StgHighBit {
<#
    .SYNOPSIS
        Configure and verify Allow High-Bit Characters settings for vulnerability 76823.

    .DESCRIPTION
        Configure and verify Allow High-Bit Characters settings for vulnerability 76823.

    .NOTES
        Tags: V-76823
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
            $PreConfigHighBit = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowHighBitCharacters

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name "allowHighBitCharacters" -Value "False"

            $PostConfigurationHighBit = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowHighBitCharacters

            [pscustomobject] @{
                Vulnerability = "V-76823"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigHighBit = $PreConfigHighBit.Value
                PostConfigurationHighBit = $PostConfigurationHighBit.Value
                Compliant = if ($PostConfigurationHighBit.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}