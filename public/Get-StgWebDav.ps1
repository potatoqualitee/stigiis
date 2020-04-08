function Get-StgWebDav {
<#
    .SYNOPSIS
        Remove Windows feature Web-DAV-Publishing for vulnerability 76713 & 76803.

    .DESCRIPTION
        Remove Windows feature Web-DAV-Publishing for vulnerability 76713 & 76803.

    .NOTES
        Tags: V-76713, V-76803
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
        $DAVFeature = 'Web-DAV-Publishing'
        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        #Remove Web-DAV-Publishing feature
        $RemoveFeature = Remove-WindowsFeature -Name $DAVFeature

        [pscustomobject] @{

            Vulnerability = 'V-76713, V-76803'
            Computername = $env:COMPUTERNAME
            FeatureName = $DAVFeature
            RemovedFeatures = $RemoveFeature.FeatureResult
            ExitCode = $RemoveFeature.ExitCode
            RestartNeeded = $RemoveFeature.RestartNeeded
            Compliant = if ($RemoveFeature.Success -eq $true) {

                "Yes"
            }

            else {

                "No"
            }
        }
    }
}