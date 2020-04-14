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

    .EXAMPLE
        PS C:\> Get-StgAppPoolEventLog -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgAppPoolEventLog -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and reports the necessary information

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
            $filterpath = "recycling.logEventOnRecycle"
            $AppPools = (Get-IISAppPool).Name

            foreach ($pool in $AppPools) {
                #Current log fields
                $CurrentPoolFields = (Get-ItemProperty -Path "IIS:\AppPools\$($pool)" -Name $filterpath).Split(",")

                #Combine STIG fields and current fields (to ensure nothing is turned off, only turned on)
                $Pool = Get-ItemProperty -Path "IIS:\AppPools\$($pool)" -Name $filterpath

                if ($Pool -like "*Time*" -and $Pool -like "*Schedule*") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id              = "V-76873"
                    ComputerName    = $env:COMPUTERNAME
                    ApplicationPool = $pool
                    Value           = $CurrentPoolFields
                    Compliant       = $compliant
                    Notes           = "Time and Scheduled logging must be turned on"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, ApplicationPool, Value, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

