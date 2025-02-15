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

    .EXAMPLE
        PS C:\> Get-StgUriRegistry -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgUriRegistry -ComputerName web01 -Credential ad\webadmin

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
            $ParameterKey = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
            [String[]]$Keys = @(
                "URIEnableCache",
                "UriMaxUriBytes",
                "UriScavengerPeriod"
            )

            foreach ($Key in $Keys) {
                $fullkey = "$ParameterKey\$Key"

                if (-not (Test-Path $fullkey)) {
                    $KeyCompliant = $false
                } else {
                    $KeyCompliant = $true
                }

                [pscustomobject] @{
                    Id           = "V-76755"
                    ComputerName = $env:COMPUTERNAME
                    Key          = $fullkey
                    Compliant    = $KeyCompliant
                    Notes        = "Key does not exist"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Key, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
