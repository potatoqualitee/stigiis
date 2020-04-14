function Set-StgAppPoolRapidFailInterval {
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

    .EXAMPLE
        PS C:\> Set-StgAppPoolRapidFailInterval -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgAppPoolRapidFailInterval -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and updates the necessary setting

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
            $pools = (Get-IISAppPool).Name

            foreach ($pool in $pools) {

                $preconfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$pool" -Name $filterpath).Value

                if ([int]([timespan]$preconfigProtectionInterval).TotalMinutes -gt 5) {

                    $null = Set-ItemProperty -Path "IIS:\AppPools\$pool" -Name $filterpath -Value $ProtectionInterval
                }

                $postconfigProtectionInterval = (Get-ItemProperty -Path "IIS:\AppPools\$pool" -Name $filterpath).Value
                if ([int]([timespan]$postconfigProtectionInterval).TotalMinutes -le 5) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id              = "V-76881"
                    ComputerName    = $env:COMPUTERNAME
                    ApplicationPool = $pool
                    Before          = [int]([timespan]$preconfigProtectionInterval).TotalMinutes
                    After           = [int]([timespan]$postconfigProtectionInterval).TotalMinutes
                    Compliant       = $compliant
                    Notes           = "Value must be 5 or less"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, ApplicationPool, Before, After, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

