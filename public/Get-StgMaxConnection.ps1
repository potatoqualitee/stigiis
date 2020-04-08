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
        [string]$PSPath = 'MACHINE/WEBROOT/APPHOST'
        [string]$FilterPath = 'system.applicationHost/sites/siteDefaults'

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        $MaxConnections = Get-WebConfigurationProperty -Filter $FilterPath -Name Limits

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