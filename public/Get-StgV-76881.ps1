function Get-StgV-76881 {
<#
    .SYNOPSIS
        Configure and verify Application Pool Rapid-Fail Inetrval settings for vulnerability 76881.

    .DESCRIPTION
        Configure and verify Application Pool Rapid-Fail Interval settings for vulnerability 76881.

    .NOTES
        Tags: V-76881
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        $FilterPath = 'failure.rapidFailProtectionInterval',

        [Parameter(DontShow)]
        $ProtectionInterval = "00:05:00"

    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        if ([Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes -gt 5) {

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $ProtectionInterval
        }

        $PostConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath).Value

        [pscustomobject] @{

            Vulnerability = "V-76881"
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigProtectionInterval = [Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes
            PostConfigProtectionInterval = [Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes
            Compliant = if ([Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes -le 5) {

                "Yes"
            }

            else {

                "No: Value must be 5 or less"
            }
        }
    }

}
