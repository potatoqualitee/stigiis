function Get-StgV-76841 {
<#
.SYNOPSIS
    Configure and verify Session Time-Out settings for vulnerability 76841.

.DESCRIPTION
    Configure and verify Session Time-Out settings for vulnerability 76841.

    .NOTES
        Tags: V-76841
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
        $FilterPath = 'system.web/sessionState'

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        foreach($WebName in $WebNames) {

            $PreConfigSessionTimeOut = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name TimeOut

            if (-not ([Int]([TimeSpan]$PreConfigSessionTimeOut.Value).TotalMinutes -le 20)) {

                Set-WebConfigurationProperty -PSPath $PSPath/$($WebName) -Filter $FilterPath -Name Timeout -Value "00:20:00"
            }

            $PostConfigSessionTimeOut = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name TimeOut

            [pscustomobject] @{
                Vulnerability = "V-76841"
                Computername = $env:COMPUTERNAME
                Sitename = $WebName
                PreConfigSessionTimeOut = [Int]([TimeSpan]$PreConfigSessionTimeOut.Value).TotalMinutes
                PostConfigSessionTimeOut = [Int]([TimeSpan]$PostConfigSessionTimeOut.Value).TotalMinutes
                Compliant = if ([Int]([TimeSpan]$PostConfigSessionTimeOut.Value).TotalMinutes -le 20) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}