function Get-StgV-76875 {
<#
.SYNOPSIS
    Configure and verify Application Pool Queue Length settings for vulnerability 76875.

.DESCRIPTION
    Configure and verify Application Pool Queue Length settings for vulnerability 76875.

    .NOTES
        Tags: V-76875
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        [string]$FilterPath = 'queueLength',

        [Parameter(DontShow)]
        [Int]$QLength = 1000
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        if ($PreConfigQLength.Value -gt 1000) {

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $QLength
        }

        $PostConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [pscustomobject] @{

            Vulnerability = "V-76875"
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigQLength = $PreConfigQLength
            PostConfigQLength = $PostConfigQLength
            Compliant = if ($PostConfigQLength -le 1000) {

                "Yes"
            }

            else {

                "No: Value must be 1000 or less"
            }
        }
    }

}
