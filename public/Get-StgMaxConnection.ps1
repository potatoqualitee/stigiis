function Get-StgMaxConnection {
<#
    .SYNOPSIS
        Verify Maximum Connection settings for vulnerability 76773.

    .DESCRIPTION
        Verify Maximum Connection settings for vulnerability 76773.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76773
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
        $filterpath = 'system.applicationHost/sites/siteDefaults'



        $MaxConnections = Get-WebConfigurationProperty -Filter $filterpath -Name Limits

        [pscustomobject] @{
            Vulnerability = "V-76773"
            Computername = $env:COMPUTERNAME
            MaxConnections = $($MaxConnections.MaxConnections)
            Compliant = if ($MaxConnections.MaxConnections -gt 0) {
                "Yes"
            } else {
                "No: Configure MaxConnections attribute higher than 0"
            }
        }
    }
}