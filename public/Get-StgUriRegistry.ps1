function Get-StgUriRegistry {
<#
    .SYNOPSIS
        Verify URI registry settings for vulnerability 76755.

    .DESCRIPTION
        Verify URI registry settings for vulnerability 76755.

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
    }
    process {
        [string]$ParameterKey = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
        [String[]]$Keys = @(
            "URIEnableCache",
            "UriMaxUriBytes",
            "UriScavengerPeriod"
            )

        Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"
        foreach($Key in $Keys) {
            $KeyCompliant = if (-not (Test-Path "$($ParameterKey)\$($Key)")) {
                "No: Key does not exist"
            } else {
                "Yes"
            }

            [pscustomobject] @{
                Vulnerability = "V-76755"
                Computername = $env:COMPUTERNAME
                Key = "$($ParameterKey)\$($Key)"
                Compliant = $KeyCompliant
            }
        }
    }
}