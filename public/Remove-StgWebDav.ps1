function Remove-StgWebDav {
<#
    .SYNOPSIS
        Remove Windows feature Web-DAV-Publishing for vulnerability 76713 & 76803.

    .DESCRIPTION
        Remove Windows feature Web-DAV-Publishing for vulnerability 76713 & 76803.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76713, V-76803
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Remove-StgWebDav -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Remove-StgWebDav -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and updates the necessary setting

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
            $DAVFeature = "Web-DAV-Publishing"

            #Remove Web-DAV-Publishing feature
            $RemoveFeature = Remove-WindowsFeature -Name $DAVFeature

            if ($RemoveFeature.Success -eq $true) {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id              = "V-76713", "V-76803"
                ComputerName    = $env:COMPUTERNAME
                FeatureName     = $DAVFeature
                RemovedFeatures = $RemoveFeature.FeatureResult
                ExitCode        = $RemoveFeature.ExitCode
                RestartNeeded   = $RemoveFeature.RestartNeeded
                Compliant       = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, FeatureName, RemovedFeatures, ExitCode, RestartNeeded, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

