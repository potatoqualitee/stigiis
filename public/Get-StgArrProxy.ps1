function Get-StgArrProxy {
    <#
    .SYNOPSIS
        Get proxy settings for Application Request Routing feature for vulnerability 76703.

    .DESCRIPTION
        Get proxy settings for Application Request Routing feature for vulnerability 76703.

        A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76703
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgArrProxy -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgArrProxy -ComputerName web01 -Credential ad\webadmin

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
            $WebPath = "MACHINE/WEBROOT/APPHOST"
            $webs = (Get-Website).Name
            $proxyvalue = Get-WebConfigurationProperty -PSPath $WebPath -Filter "system.webServer/proxy" -Name "Enabled"

            # gotta be one or th other
            if ($webs.Count -gt 1 -and $proxyvalue) {
                [pscustomobject]@{
                    Id           = "V-76703"
                    ComputerName = $env:COMPUTERNAME
                    Proxies      = $proxy
                    Webs         = $webs
                    Compliant    = $false
                }
            } else {
                [pscustomobject]@{
                    Id           = "V-76703"
                    ComputerName = $env:COMPUTERNAME
                    Proxies      = $proxy
                    Webs         = $webs
                    Compliant    = $true
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Proxies, Webs, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
