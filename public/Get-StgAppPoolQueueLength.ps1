function Get-StgAppPoolQueueLength {
<#
    .SYNOPSIS
        Configure and verify Application Pool Queue Length settings for vulnerability 76875.

    .DESCRIPTION
        Configure and verify Application Pool Queue Length settings for vulnerability 76875.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

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
        $scriptblock = {
            $filterpath = "queueLength"
            $QLength = 1000
            $AppPools = (Get-IISAppPool).Name

            foreach($Pool in $AppPools) {

                $PreConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

                if ($PreConfigQLength.Value -gt 1000) {

                    Set-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath -Value $QLength
                }

                $PostConfigQLength = (Get-ItemProperty -Path "IIS:\AppPools\$($Pool)" -Name $filterpath).Value

                [pscustomobject] @{
                    Vulnerability = "V-76875"
                    ComputerName = $env:ComputerName
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