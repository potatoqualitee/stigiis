function Get-StgSessionSecurity {
    <#
    .SYNOPSIS
        Get Session Security settings for vulnerability 76757 & 76855.

    .DESCRIPTION
        Get Session Security settings for vulnerability 76757 & 76855.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76757, V-76855
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgSessionSecurity -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgSessionSecurity -ComputerName web01 -Credential ad\webadmin

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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/asp/session"
            $config = Get-WebConfigurationProperty -Filter $filterpath  -Name KeepSessionIdSecure

            if ($config.Value -eq "True") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id                         = "V-76757"
                ComputerName               = $env:COMPUTERNAME
                SiteName                   = $env:COMPUTERNAME
                Value                      = $config.Value
                Compliant                  = $compliant
            }

            foreach ($webname in $webnames) {
                $config = Get-WebConfigurationProperty -Location $webname -Filter $filterpath  -Name KeepSessionIdSecure

                if ($config.Value -eq $true) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76855"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Value        = $config.Value
                    Compliant    = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Value, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
