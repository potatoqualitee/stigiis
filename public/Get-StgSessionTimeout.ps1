function Get-StgSessionTimeout {
<#
    .SYNOPSIS
        Configure and verify Session Time-Out settings for vulnerability 76841.

    .DESCRIPTION
        Configure and verify Session Time-Out settings for vulnerability 76841.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

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
        $scriptblock = {
            $webnames = (Get-Website).Name
            $filterpath = "system.web/sessionState"
            foreach($webname in $webnames) {

                $PreConfigSessionTimeOut = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name TimeOut

                if (-not ([Int]([TimeSpan]$PreConfigSessionTimeOut.Value).TotalMinutes -le 20)) {

                    Set-WebConfigurationProperty -PSPath $pspath/$($webname) -Filter $filterpath -Name Timeout -Value "00:20:00"
                }

                $PostConfigSessionTimeOut = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name TimeOut

                [pscustomobject] @{
                    Id = "V-76841"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfigSessionTimeOut = [Int]([TimeSpan]$PreConfigSessionTimeOut.Value).TotalMinutes
                    PostConfigSessionTimeOut = [Int]([TimeSpan]$PostConfigSessionTimeOut.Value).TotalMinutes
                    Compliant = if ([Int]([TimeSpan]$PostConfigSessionTimeOut.Value).TotalMinutes -le 20) {
                        $true
                    } else {
                        $false
                    }
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