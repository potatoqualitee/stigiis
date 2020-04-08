function Get-StgV-76839 {
<#
.SYNOPSIS
    Configure and verify Application Pool Time-Out settings for vulnerability 76839.

.DESCRIPTION
    Configure and verify Application Pool Time-Out settings for vulnerability 76839.

    .NOTES
        Tags: V-76839
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        [string]$PSPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.applicationHost/applicationPools/applicationPoolDefaults/processModel'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PreConfigTimeOut = Get-WebConfigurationProperty -Filter $FilterPath -Name idleTimeOut

    if (-not ([Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes -le 20)) {

        Set-WebConfigurationProperty -PSPath $PSPath -Filter $FilterPath -Name idleTimeout -Value "00:20:00"
    }

    $PostConfigTimeOut = Get-WebConfigurationProperty -Filter $FilterPath -Name idleTimeOut

    [pscustomobject] @{

        Vulnerability = "V-76839"
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigTimeOut = [Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes
        PostConfigTimeOut = [Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes
        Compliant = if ([Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes -le 20) {

            "Yes"
        }

        else {

            "No"
        }
    }

}
