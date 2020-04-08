function Get-StgV-76877 {
<#
    .SYNOPSIS
        Configure and verify Application Pool Ping settings for vulnerability 76877.

    .DESCRIPTION
        Configure and verify Application Pool Ping settings for vulnerability 76877.

    .NOTES
        Tags: V-76877
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        [string]$FilterPath = 'processModel.pingingEnabled'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigPing = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $true

        $PostConfigPing = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [pscustomobject] @{

            Vulnerability = "V-76877"
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigPing = $PreConfigPing
            PostConfigPing = $PostConfigPing
            Compliant = if ($PostConfigPing -eq $true) {

                "Yes"
            }

            else {

                "No"
            }
        }
    }

}