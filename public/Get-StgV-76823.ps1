function Get-StgV-76823 {
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
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webServer/security/requestFiltering'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

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
            }

            else {

                "No"
            }
        }
    }

}
