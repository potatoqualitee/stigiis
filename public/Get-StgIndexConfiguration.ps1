function Get-StgIndexConfiguration {
<#
    .SYNOPSIS
        Get Indexing configurations for vulnerability 76735.

    .DESCRIPTION
        Get Indexing configurations for vulnerability 76735.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76735
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgIndexConfiguration -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgIndexConfiguration -ComputerName web01 -Credential ad\webadmin

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
            $RegPath = "HKLM:\System\CurrentControlSet\Control\ContentIndex\Catalogs"

            if (-not (Test-Path $RegPath)) {
                [pscustomobject]@{
                    Id           = "V-76735"
                    ComputerName = $env:COMPUTERNAME
                    Key          = $RegPath
                    Compliant    = $true
                    Notes        = "Not Applicable: key does not exist"
                }
            } else {
                [pscustomobject]@{
                    Id           = "V-76735"
                    ComputerName = $env:COMPUTERNAME
                    Key          = $RegPath
                    Compliant    = $true
                    Notes        = "Key exists; check Indexing Service snap-in from MMC console"
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
