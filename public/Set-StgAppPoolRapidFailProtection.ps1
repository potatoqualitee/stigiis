function Set-StgAppPoolRapidFailProtection {
    <#
    .SYNOPSIS
        Configure and verify Application Pool Rapid-Fail Protection settings for vulnerability 76879.

    .DESCRIPTION
        Configure and verify Application Pool Rapid-Fail Protection settings for vulnerability 76879.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76879
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgAppPoolRapidFailProtection -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgAppPoolRapidFailProtection -ComputerName web01 -Credential ad\webadmin

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
            $filterpath = "failure.rapidFailProtection"
            $AppPools = (Get-IISAppPool).Name

            foreach ($pool in $AppPools) {

                $preconfigRapidFailEnabled = (Get-ItemProperty -Path "IIS:\AppPools\$($pool)" -Name $filterpath).Value

                Set-ItemProperty -Path "IIS:\AppPools\$($pool)" -Name $filterpath -Value $true

                $postconfigRapidFailEnabled = (Get-ItemProperty -Path "IIS:\AppPools\$($pool)" -Name $filterpath).Value
                if ($postconfigRapidFailEnabled -eq $true) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id              = "V-76877"
                    ComputerName    = $env:COMPUTERNAME
                    ApplicationPool = $pool
                    Before          = $preconfigRapidFailEnabled
                    After           = $postconfigRapidFailEnabled
                    Compliant       = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, ApplicationPool, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

