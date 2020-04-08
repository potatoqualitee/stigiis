function Get-StgAppPoolTimeout {
<#
    .SYNOPSIS
        Configure and verify Application Pool Time-Out settings for vulnerability 76839.

    .DESCRIPTION
        Configure and verify Application Pool Time-Out settings for vulnerability 76839.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76839
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
        $pspath = 'MACHINE/WEBROOT/APPHOST'
        $filterpath = 'system.applicationHost/applicationPools/applicationPoolDefaults/processModel'



        $PreConfigTimeOut = Get-WebConfigurationProperty -Filter $filterpath -Name idleTimeOut

        if (-not ([Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes -le 20)) {

            Set-WebConfigurationProperty -PSPath $pspath -Filter $filterpath -Name idleTimeout -Value "00:20:00"
        }

        $PostConfigTimeOut = Get-WebConfigurationProperty -Filter $filterpath -Name idleTimeOut

        [pscustomobject] @{
            Vulnerability = "V-76839"
            Computername = $env:COMPUTERNAME
            Sitename = $env:COMPUTERNAME
            PreConfigTimeOut = [Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes
            PostConfigTimeOut = [Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes
            Compliant = if ([Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes -le 20) {
                "Yes"
            } else {
                "No"
            }
        }
    }
}