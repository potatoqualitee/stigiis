function Get-StgAppPoolRecycle {
<#
    .SYNOPSIS
        Configure and verify Application Pool Recycling settings for vulnerability 76867.

    .DESCRIPTION
        Configure and verify Application Pool Recycling settings for vulnerability 76867.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76867
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
            $filterpath = "recycling.periodicRestart.requests"
            $RequestsDefault = 100000
            $AppPools = (Get-IISAppPool).Name

            foreach($Pool in $AppPools) {

                $PreConfigRecycle = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath

                if ($PreConfigRecycle -eq 0) {

                    Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $RequestsDefault
                }

                $PostConfigRecycle = Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath

                [pscustomobject]@{
                    Id = "V-76867"
                    ComputerName = $env:ComputerName
                    ApplicationPool = $Pool
                    PreConfigRecycle = $PreConfigRecycle.Value
                    PostConfigRecycle = $PostConfigRecycle.Value
                    Compliant = if ($PostConfigRecycle.Value -gt 0) {
                        $true
                    } else {
                        "No: Value must be set higher than 0"
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