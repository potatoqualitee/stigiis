function Get-StgFso {
<#
    .SYNOPSIS
        Verify File System Component settings for vulnerability 76767.

    .DESCRIPTION
        Verify File System Component settings for vulnerability 76767.

        Some Component Object Model (COM) components are not required for most applications and should be removed if possible. Most notably, consider disabling the File System Object component; however, this will also remove the Dictionary object. Be aware some programs may require this component (e.g., Commerce Server), so it is highly recommended this be tested completely before implementing on the production web server.

    .NOTES
        Tags: V-76767
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
        $FSOKey = "HKCR:\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"

        Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"

        New-PSDrive -PSProvider Registry -root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

        $ComponentEnabled = if (Test-Path $FSOKey) {
            "Enabled"
        } else {
            "Disabled"
        }

        $Compliant = if (Test-Path $FSOKey) {
            "No: Key exists. If component is NOT required for operations, run: regsvr32 scrrun.dll /u to unregister this library. Note: If the File System Object component is required for operations and has supporting documentation signed by the ISSO, this is not a finding."
        } else {
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
}