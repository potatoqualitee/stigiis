function Get-StgV-76735 {
<#
    .SYNOPSIS
        Configure and verify Indexing configurations for vulnerability 76735.

    .DESCRIPTION
        Configure and verify Indexing configurations for vulnerability 76735.

    .NOTES
        Tags: V-76735
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        [string] $RegPath = "HKLM:\System\CurrentControlSet\Control\ContentIndex\Catalogs"
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    if(!(Test-Path $RegPath)) {

        [pscustomobject] @{

            Vulnerability = "V-76735"
            Computername = $env:COMPUTERNAME
            Key = $RegPath
            Compliant = "Not Applicable: Key does not exist"
        }
    }

    else {

        [pscustomobject] @{

            Vulnerability = "V-76735"
            Computername = $env:COMPUTERNAME
            Key = $RegPath
            Compliant = "No: Key exists; check Indexing Service snap-in from MMC console"
        }

    }

}
