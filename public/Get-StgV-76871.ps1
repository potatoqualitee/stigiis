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
    param(

        [Parameter(DontShow)]
        [string]$FilterPath = 'recycling.periodicRestart.privateMemory',

        [Parameter(DontShow)]
        [Int64]$MemoryDefault = 1GB
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $AppPools = (Get-IISAppPool).Name

    foreach($Pool in $AppPools) {

        $PreConfigMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        if ($PreConfigMemory -eq 0) {

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath -Value $MemoryDefault
        }

        $PostConfigMemory = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $FilterPath

        [pscustomobject] @{

            Vulnerability = "V-76871"
            Computername = $env:COMPUTERNAME
            ApplicationPool = $Pool
            PreConfigMemory = [string]$PreConfigMemory.Value
            PostConfigMemory = [string]$PostConfigMemory.Value
            Compliant = if ($PostConfigMemory.Value -gt 0) {

                "Yes"
            }

            else {

                "No: Value must be set higher than 0"
            }
        }
    }

}
