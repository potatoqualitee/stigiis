function Get-StgPrintService {
<#
    .SYNOPSIS
        Configure and verify Print Services settings for vulnerability 76753.

    .DESCRIPTION
        Configure and verify Print Services settings for vulnerability 76753.

    .NOTES
        Tags: V-76753
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
        $PrintPath = "$($env:windir)\web\printers"
        $PrintServices = @("Print-Services", "Print-Internet")



        $PrintFeatures = Get-WindowsFeature -Name $PrintServices

        foreach($Feature in $PrintFeatures) {
            [pscustomobject] @{
                Vulnerability = "V-76753"
                Computername = $env:COMPUTERNAME
                Feature = $Feature.Name
                InstallState = $Feature.InstallState
                Compliant = if ($Feature.InstallState -eq "Available") {
                    "Yes"
                } else {
                    "No: Remove $($Feature.Name) Windows Feature"
                }
            }
        }
    }
}
