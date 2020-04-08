function Get-StgV-76871 {
<#
.SYNOPSIS
    Configure and verify Application Pool Private Memory Recycling settings for vulnerability 76871.

.DESCRIPTION
    Configure and verify Application Pool Private Memory Recycling settings for vulnerability 76871.

    .NOTES
        Tags: V-76871
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
        $filterpath = 'recycling.periodicRestart.privateMemory'
        $MemoryDefault = 1GB



        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {

            $PreConfigMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath

            if ($PreConfigMemory -eq 0) {

                Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $MemoryDefault
            }

            $PostConfigMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath

            [pscustomobject] @{
                Vulnerability = "V-76871"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigMemory = [string]$PreConfigMemory.Value
                PostConfigMemory = [string]$PostConfigMemory.Value
                Compliant = if ($PostConfigMemory.Value -gt 0) {
                    "Yes"
                } else {
                    "No: Value must be set higher than 0"
                }
            }
        }
    }
}