function Get-StgAppPoolRecyclePrivateMemory {
<#
    .SYNOPSIS
        Configure and verify Application Pool Private Memory Recycling settings for vulnerability 76871.

    .DESCRIPTION
        Configure and verify Application Pool Private Memory Recycling settings for vulnerability 76871.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

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
        $filterpath = "recycling.periodicRestart.privateMemory"
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