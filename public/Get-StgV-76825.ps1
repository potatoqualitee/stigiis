function Get-StgV-76825 {
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
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webServer/security/requestFiltering'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($WebName in $WebNames) {

        $PreConfigDoubleEscaping = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowDoubleEscaping

        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name allowDoubleEscaping -Value "False"

        $PostConfigurationDoubleEscaping = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name allowDoubleEscaping

        [pscustomobject] @{

            Vulnerability = "V-76825"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigDoubleEscaping = $PreConfigDoubleEscaping.Value
            PostConfigurationDoubleEscaping = $PostConfigurationDoubleEscaping.Value
            Compliant = if($PostConfigurationDoubleEscaping.Value -eq $false) {

                "Yes"
            }

            else {

                "No"
            }
        }
    }

}
