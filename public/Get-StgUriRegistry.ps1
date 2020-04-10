function Get-StgUriRegistry {
<#
    .SYNOPSIS
        Verify URI registry settings for vulnerability 76755.

    .DESCRIPTION
        Verify URI registry settings for vulnerability 76755.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76755
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
            $ParameterKey = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
            [String[]]$Keys = @(
                "URIEnableCache",
                "UriMaxUriBytes",
                "UriScavengerPeriod"
                )

            foreach($Key in $Keys) {
                $KeyCompliant = if (-not (Test-Path "$($ParameterKey)\$($Key)")) {
                    "No: Key does not exist"
                } else {
                    $true
                }

                [pscustomobject] @{
                    Id = "V-76755"
                    ComputerName = $env:ComputerName
                    Key = "$($ParameterKey)\$($Key)"
                    Compliant = $KeyCompliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}