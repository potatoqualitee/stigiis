function Get-StgV-76867 {
<#
    .SYNOPSIS
        Configure and verify Application Pool Recycling settings for vulnerability 76867.

    .DESCRIPTION
        Configure and verify Application Pool Recycling settings for vulnerability 76867.

    .NOTES
        Tags: V-76867
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        $FilterPath = 'recycling.periodicRestart.requests',

        [Parameter(DontShow)]
        [Int64]$RequestsDefault = 100000
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigRecycle = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        if ($PreConfigRecycle -eq 0) {

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $RequestsDefault
        }

        $PostConfigRecycle = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        [pscustomobject] @{

            Vulnerability = "V-76867"
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigRecycle = $PreConfigRecycle.Value
            PostConfigRecycle = $PostConfigRecycle.Value
            Compliant = if ($PostConfigRecycle.Value -gt 0) {

                "Yes"
            }

            else {

                "No: Value must be set higher than 0"
            }
        }
    }

}
