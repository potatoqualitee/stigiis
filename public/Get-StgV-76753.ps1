function Get-StgV-76753 {
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
    param(

        [Parameter(DontShow)]
        [string]$PrintPath = "$($env:windir)\web\printers",

        [Parameter(DontShow)]
        [String[]]$PrintServices = @("Print-Services", "Print-Internet")
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PrintFeatures = Get-WindowsFeature -Name $PrintServices

    foreach($Feature in $PrintFeatures) {

        [pscustomobject] @{

            Vulnerability = "V-76753"
            Computername = $env:COMPUTERNAME
            Feature = $Feature.Name
            InstallState = $Feature.InstallState
            Compliant = if($Feature.InstallState -eq "Available") {

                "Yes"
            }

            else {

                "No: Remove $($Feature.Name) Windows Feature"
            }
        }
    }

}
