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
        $scriptblock = {
            $filterpath = "failure.rapidFailProtectionInterval"
            $ProtectionInterval = "00:05:00"
            $AppPools = (Get-IISAppPool).Name

            foreach($Pool in $AppPools) {

                $PreConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

                if ([Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes -gt 5) {

                    Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $ProtectionInterval
                }

                $PostConfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

                [pscustomobject] @{
                    Id = "V-76881"
                    ComputerName = $env:ComputerName
                    ApplicationPool = $Pool
                    PreConfigProtectionInterval = [Int]([TimeSpan]$PreConfigProtectionInterval).TotalMinutes
                    PostConfigProtectionInterval = [Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes
                    Compliant = if ([Int]([TimeSpan]$PostConfigProtectionInterval).TotalMinutes -le 5) {
                        $true
                    } else {
                        "No: Value must be 5 or less"
                    }
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property ComputerName, Id, Sitename, Hostname, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}