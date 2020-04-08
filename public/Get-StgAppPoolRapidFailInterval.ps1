function Get-StgAppPoolRapidFailInterval {
<#
    .SYNOPSIS
        Configure and verify Application Pool Rapid-Fail Interval settings for vulnerability 76881.

    .DESCRIPTION
        Configure and verify Application Pool Rapid-Fail Interval settings for vulnerability 76881.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76881
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
        $filterpath = "failure.rapidFailProtectionInterval"
        $ProtectionInterval = "00:05:00"

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        $AppPools = (Get-IISAppPool).Name

        foreach($Pool in $AppPools) {

            $PreConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            if ([Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes -gt 5) {

                Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $ProtectionInterval
            }

            $PostConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

            [pscustomobject] @{
                Vulnerability = "V-76881"
                Computername = $env:COMPUTERNAME
                ApplicationPool = $Pool
                PreConfigProtectionInterval = [Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes
                PostConfigProtectionInterval = [Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes
                Compliant = if ([Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes -le 5) {
                    "Yes"
                } else {
                    "No: Value must be 5 or less"
                }
            }
        }
    }
}