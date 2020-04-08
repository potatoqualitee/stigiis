function Get-StgLogSetting {
<#
    .SYNOPSIS
        Check, configure, and verify baseline logging setting for vulnerability 76683 & 76785.

    .DESCRIPTION
        Check, configure, and verify baseline logging setting for vulnerability 76683 & 76785.

    .NOTES
        Tags: V-76683, V-76785
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [PSFComputer[]]$ComputerName,
        [PSCredential]$Credential,
        [string]$WebPath = 'MACHINE/WEBROOT/APPHOST',
        [string]$FilterPath = "system.applicationHost/sites/sitedefaults/logfile",
        [string]$LogTarget = "logTargetW3C",
        [string]$LogValues = "File,ETW",
        [switch]$EnableException
    )
    begin {
        . "$script:ModuleRoot\private\Set-Defaults.ps1"
    }
    process {
        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        #Get pre-configuration values
        $PreWeb = Get-WebConfigurationProperty -PSPath $WebPath -Filter $FilterPath -Name $LogTarget
        $PreWeb = $PreWeb.Split(",")

        #Output which radio buttons are set
        $PreWeb = @(

            if ($PreWeb -notcontains "ETW") {

                "Log File Only"
            }

            elseif ($PreWeb -notcontains "File") {

                "ETW Event Only"
            }

            else {

                "Both log file and ETW Event"
            }
        )

        #Set Logging options to log file and ETW events (both)
        Set-WebConfigurationProperty -PSPath $WebPath -Filter $FilterPath -Name $LogTarget -Value $LogValues

        Start-Sleep -Seconds 2
        #Get pre-configuration values
        $PostWeb = Get-WebConfigurationProperty -PSPath $WebPath -Filter $FilterPath -Name $LogTarget
        $PostWeb = $PostWeb.Split(",")

        #Output which radio buttons are set
        $PostWeb = @(

            if ($PostWeb -notcontains "ETW") {

                "Log File Only"
            }

            elseif ($PostWeb -notcontains "File") {

                "ETW Event Only"
            }

            else {

                "Both log file and ETW Event"
            }
        )

        [pscustomobject] @{

            Vulnerability = 'V-76683, V-76785'
            PreConfig = "$PreWeb"
            PostConfiguration = "$PostWeb"
            Compliant = if ($PostWeb -eq "Both log file and ETW Event") {

                "Yes"
            }

            else {

                "No"
            }
        }
    }
}