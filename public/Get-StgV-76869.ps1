function Get-StgV-76869 {
<#
    .SYNOPSIS
        Configure and verify Application Pool Virtual Memory Recycling settings for vulnerability 76869.

    .DESCRIPTION
        Configure and verify Application Pool Virtual Memory Recycling settings for vulnerability 76869.

    .NOTES
        Tags: V-76869
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
        $FilterPath = 'recycling.periodicRestart.memory'
        $VMemoryDefault = 1GB



        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {
            $PreConfigVMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

            if ($PreConfigVMemory -eq 0) {

                Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $VMemoryDefault
            }

            $PostConfigVMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

            [pscustomobject] @{
                Vulnerability = "V-76869"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigVMemory = $PreConfigVMemory.Value
                PostConfigVMemory = $PostConfigVMemory.Value
                Compliant = if ($PostConfigVMemory.Value -gt 0) {
                    "Yes"
                } else {
                    "No: Value must be set higher than 0"
                }
            }
        }
    }
}