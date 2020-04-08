function Get-StgV-76709 {
<#
    .SYNOPSIS
        Report installed Windows Features for vulnerability 76709.

    .DESCRIPTION
        Report installed Windows Features for vulnerability 76709.

    .NOTES
        Tags: V-76709
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>

    Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"

    #Get all installed Windows Features
    $Features = Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed' -or $_.InstallState -eq 'InstallPending'}

    foreach($Feature in $Features) {

        [pscustomobject] @{

            Computername = $env:COMPUTERNAME
            Name = $Feature.Name
            InstallState = $Feature.InstallState
        }
    }

}
