function Get-StgAppPoolEventLog {
<#
    .SYNOPSIS
        Configure and verify Application Pool Event Log settings for vulnerability 76873.

    .DESCRIPTION
        Configure and verify Application Pool Event Log settings for vulnerability 76873.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76873
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
        $filterpath = "recycling.logEventOnRecycle"
        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {

        #STIG required log fields
        $RequiredPoolFields = @(

            "Time",
            "Schedule"
        )

        #Current log fields
        $CurrentPoolFields = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Split(",")

        #Combine STIG fields and current fields (to ensure nothing is turned off, only turned on)
        [String[]]$PoolCollection = @(
            $RequiredPoolFields
            $CurrentPoolFields
        )

        [string]$PoolCollectionString = ($PoolCollection | Select-Object -Unique)

        $PoolReplace = $PoolCollectionString.Replace(" ",",")

            $PreConfigPool = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $PoolReplace

            $PostConfigPool = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath

            [pscustomobject] @{
                Vulnerability = "V-76873"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigPool = $PreConfigPool
                PostConfigPool = $PostConfigPool
                Compliant = if ($PostConfigPool -like "*Time*" -and $PostConfigPool -like "*Schedule*") {
                    "Yes"
                } else {
                    "No: Time and Scheduled logging must be turned on"
                }
            }
        }
    }
}
