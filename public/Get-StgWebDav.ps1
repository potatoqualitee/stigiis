function Get-StgWebDav {
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
        PS C:\> Get-StgWebDav -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgWebDav -ComputerName web01 -Credential ad\webadmin

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
            $feature = Get-WindowsFeature -Name "Web-DAV-Publishing"
            if ($feature) {
                $compliant = $false
                $exists = $true
            } else {
                $compliant = $true
                $exists = $false
            }

            [pscustomobject] @{
                Id           = "V-76713", "V-76803"
                ComputerName = $env:COMPUTERNAME
                Exists       = $exists
                Compliant    = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Exists, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
