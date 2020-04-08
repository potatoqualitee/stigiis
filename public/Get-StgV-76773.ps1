function Get-StgV-76773 {

    .NOTES
        Tags: V-76773
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

<#
.SYNOPSIS
    Verify Maximum Connection settings for vulnerability 76773.

.DESCRIPTION
    Verify Maximum Connection settings for vulnerability 76773.
#>
    param(

        [Parameter(DontShow)]
        [string]$PSPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.applicationHost/sites/siteDefaults'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $MaxConnections = Get-WebConfigurationProperty -Filter $FilterPath -Name Limits

    [pscustomobject] @{

        Vulnerability = "V-76773"
        Computername = $env:COMPUTERNAME
        MaxConnections = $($MaxConnections.MaxConnections)
        Compliant = if($MaxConnections.MaxConnections -gt 0) {

            "Yes"
        }

        else {

            "No: Configure MaxConnections attribute higher than 0"
        }
    }

}
