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
        $WebNames = (Get-Website).Name
        $FilterPath = 'system.webServer/security/requestFiltering'



        foreach($WebName in $WebNames) {
            $PreConfigHighBit = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowHighBitCharacters

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name "allowHighBitCharacters" -Value "False"

            $PostConfigurationHighBit = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowHighBitCharacters

            [pscustomobject] @{
                Vulnerability = "V-76823"
                Computername = $env:COMPUTERNAME
                Sitename = $WebName
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