function Get-StgIndexConfiguration {
<#
    .SYNOPSIS
        Configure and verify Indexing configurations for vulnerability 76735.

    .DESCRIPTION
        Configure and verify Indexing configurations for vulnerability 76735.

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
        $RegPath = "HKLM:\System\CurrentControlSet\Control\ContentIndex\Catalogs"


        if (-not (Test-Path $RegPath)) {
            [pscustomobject] @{
                Vulnerability = "V-76735"
                Computername = $env:COMPUTERNAME
                Key = $RegPath
                Compliant = "Not Applicable: Key does not exist"
            }
        } else {
            [pscustomobject] @{
                Vulnerability = "V-76735"
                Computername = $env:COMPUTERNAME
                Key = $RegPath
                Compliant = "No: Key exists; check Indexing Service snap-in from MMC console"
            }
        }
    }
}