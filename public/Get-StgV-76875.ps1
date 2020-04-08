function Get-StgV-76875 {
<#
.SYNOPSIS
    Configure and verify Application Pool Queue Length settings for vulnerability 76875.

.DESCRIPTION
    Configure and verify Application Pool Queue Length settings for vulnerability 76875.

    .NOTES
        Tags: V-76875
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
        $filterpath = 'queueLength'
        [Int]$QLength = 1000



        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {

            $PreConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            if ($PreConfigQLength.Value -gt 1000) {

                Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $QLength
            }

            $PostConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            [pscustomobject] @{
                Vulnerability = "V-76875"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigQLength = $PreConfigQLength
                PostConfigQLength = $PostConfigQLength
                Compliant = if ($PostConfigQLength -le 1000) {
                    "Yes"
                } else {
                    "No: Value must be 1000 or less"
                }
            }
        }
    }
}