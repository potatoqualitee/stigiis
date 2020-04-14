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

    .EXAMPLE
        PS C:\> Get-StgAppPoolTimeout -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgAppPoolTimeout -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and reports the necessary information
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
        $scriptblock = {
            $pspath = "MACHINE/WEBROOT/APPHOST"
            $filterpath = "system.applicationHost/applicationPools/applicationPoolDefaults/processModel"
            $TimeOut = Get-WebConfigurationProperty -Filter $filterpath -Name idleTimeOut

            if (-not ([Int]([TimeSpan]$TimeOut.Value).TotalMinutes -le 20)) {
                Set-WebConfigurationProperty -PSPath $pspath -Filter $filterpath -Name idleTimeout -Value "00:20:00"
            }

            $postconfigTimeOut = Get-WebConfigurationProperty -Filter $filterpath -Name idleTimeOut
            if ([Int]([TimeSpan]$postconfigTimeOut.Value).TotalMinutes -le 20) {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id              = "V-76839"
                ComputerName    = $env:COMPUTERNAME
                Value          = [Int]([TimeSpan]$TimeOut.Value).TotalMinutes
                After           = [Int]([TimeSpan]$postconfigTimeOut.Value).TotalMinutes
                Compliant       = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Value, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
