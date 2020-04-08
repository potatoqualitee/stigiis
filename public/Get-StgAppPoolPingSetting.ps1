function Get-StgAppPoolPingSetting {
<#
    .SYNOPSIS
        Configure and verify Application Pool Ping settings for vulnerability 76877.

    .DESCRIPTION
        Configure and verify Application Pool Ping settings for vulnerability 76877.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76877
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
        $filterpath = "processModel.pingingEnabled"

        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {

            $PreConfigPing = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $true

            $PostConfigPing = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            [pscustomobject] @{

                Vulnerability = "V-76877"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigPing = $PreConfigPing
                PostConfigPing = $PostConfigPing
                Compliant = if ($PostConfigPing -eq $true) {

                    "Yes"
                }

                else {

                    "No"
                }
            }
        }
    }
}