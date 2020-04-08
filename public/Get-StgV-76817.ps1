function Get-StgV-76817 {
<#
    .SYNOPSIS
        Configure and verify URL Request Limit settings for vulnerability 76817.

    .DESCRIPTION
        Configure and verify URL Request Limit settings for vulnerability 76817.

    .NOTES
        Tags: V-76817
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webServer/security/requestFiltering/requestLimits',

        [Int]$MaxUrl = 4096
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($WebName in $WebNames) {

        $PreConfigMaxUrl = Get-WebConfigurationProperty -Filter $FilterPath -Name MaxUrl

        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name MaxUrl -Value $MaxUrl -Force

        $PostConfigurationMaxUrl = Get-WebConfigurationProperty -Filter $FilterPath -Name MaxUrl

        [pscustomobject] @{

            Vulnerability = "V-76817"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfiugrationMaxUrl = $PreConfigMaxUrl.Value
            PostConfiugrationMaxUrl = $PostConfigurationMaxUrl.Value
            Compliant = if ($PostConfigurationMaxUrl.Value -le $MaxUrl) {

                "Yes"
            }

            else {

                "No: Value must be $MaxUrl or less"
            }
        }
    }

}
