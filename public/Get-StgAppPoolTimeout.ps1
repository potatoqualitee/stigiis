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
        $scriptblock = {
            $pspath = "MACHINE/WEBROOT/APPHOST"
            $filterpath = "system.applicationHost/applicationPools/applicationPoolDefaults/processModel"
            $PreConfigTimeOut = Get-WebConfigurationProperty -Filter $filterpath -Name idleTimeOut

            if (-not ([Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes -le 20)) {

                Set-WebConfigurationProperty -PSPath $pspath -Filter $filterpath -Name idleTimeout -Value "00:20:00"
            }

            $PostConfigTimeOut = Get-WebConfigurationProperty -Filter $filterpath -Name idleTimeOut

            [pscustomobject] @{
                Id = "V-76839"
                ComputerName = $env:ComputerName
                Sitename = $env:ComputerName
                PreConfigTimeOut = [Int]([TimeSpan]$PreConfigTimeOut.Value).TotalMinutes
                PostConfigTimeOut = [Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes
                Compliant = if ([Int]([TimeSpan]$PostConfigTimeOut.Value).TotalMinutes -le 20) {
                    $true
                } else {
                    $false
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property ComputerName, Id, Sitename, Hostname, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}