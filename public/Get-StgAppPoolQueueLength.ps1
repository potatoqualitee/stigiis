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

    .EXAMPLE
        PS C:\> Get-StgAppPoolQueueLength -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgAppPoolQueueLength -ComputerName web01 -Credential ad\webadmin

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
            $filterpath = "queueLength"
            $QLength = 1000
            $AppPools = (Get-IISAppPool).Name

            foreach ($pool in $AppPools) {
                $QLength = (Get-ItemProperty -Path "IIS:\AppPools\$($pool)" -Name $filterpath).Value
                if ($QLength -le $QLength) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id              = "V-76875"
                    ComputerName    = $env:COMPUTERNAME
                    ApplicationPool = $pool
                    Valuee           = $QLengt
                    Compliant       = $compliant
                    Notes           = "Value must be 1000 or less"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, ApplicationPool, Value,  After, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
