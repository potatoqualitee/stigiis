function Get-StgV-76821 {
<#
    .SYNOPSIS
        Configure and verify Maximum Query String settings for vulnerability 76821.

    .DESCRIPTION
        Configure and verify Maximum Query String settings for vulnerability 76821.

    .NOTES
        Tags: V-76821
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webServer/security/requestFiltering/requestLimits',

        [Int]$MaxQueryString = 2048
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($WebName in $WebNames) {

        $PreConfigMaxQueryString = Get-WebConfigurationProperty -Filter $FilterPath -Name maxQueryString

        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name maxQueryString -Value $MaxQueryString -Force

        $PostConfigurationMaxQueryString = Get-WebConfigurationProperty -Filter $FilterPath -Name maxQueryString

        [pscustomobject] @{

            Vulnerability = "V-76821"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfiugrationMaxQueryString = $PreConfigMaxQueryString.Value
            PostConfiugrationMaxQueryString = $PostConfigurationMaxQueryString.Value
            Compliant = if ($PostConfigurationMaxQueryString.Value -le $MaxQueryString) {

                "Yes"
            }

            else {

                "No: Value must be $MaxQueryString or less"
            }
        }
    }

}
