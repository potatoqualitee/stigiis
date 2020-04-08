function Get-StgMaxConnection {
<#
    .SYNOPSIS
        Verify Maximum Connection settings for vulnerability 76773.

    .DESCRIPTION
        Verify Maximum Connection settings for vulnerability 76773.

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