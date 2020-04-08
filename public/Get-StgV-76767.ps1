function Get-StgV-76767 {

    .NOTES
        Tags: V-76767
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

<#
.SYNOPSIS
    Verify File System Component settings for vulnerability 76767.

.DESCRIPTION
    Verify File System Component settings for vulnerability 76767.
#>
    param(

        [string] $FSOKey = "HKCR:\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"
    )

    Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"

    New-PSDrive -PSProvider Registry -root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

    $ComponentEnabled = if(Test-Path $FSOKey) {

        "Enabled"
    }

    else {

        "Disabled"
    }

    $Compliant = if(Test-Path $FSOKey) {

        "No: Key exists. If component is NOT required for operations, run: regsvr32 scrrun.dll /u to unregister this library. Note: If the File System Object component is required for operations and has supporting documentation signed by the ISSO, this is not a finding."
    }

    else {

        "Yes"
    }

    [pscustomobject] @{

        Vulnerability = "V-76767"
        Computername = $env:COMPUTERNAME
        Key = $FSOKey
        ComponentStatus = $ComponentEnabled
        Compliant = $Compliant
    }

}
