function Get-StgAltHostname {
<#
    .SYNOPSIS
        Configure and verify Alternate Hostname settings for vulnerability 76883.

    .DESCRIPTION
        Configure and verify Alternate Hostname settings for vulnerability 76883.

        When using static HTML pages, a Content-Location header is added to the response. The Internet Information Server (IIS) Content-Location may reference the IP address of the server, rather than the Fully Qualified Domain Name (FQDN) or Hostname. This header may expose internal IP addresses that are usually hidden or masked behind a Network Address Translation (NAT) firewall or proxy server. There is a value that can be modified in the IIS metabase to change the default behavior from exposing IP addresses, to sending the FQDN instead.

        If “alternateHostName” has no assigned value, this is a finding.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76883
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgAltHostname -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgAltHostname -ComputerName web01 -Credential ad\webadmin

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
            foreach($webname in $webnames) {
                $config = (Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/serverRuntime" -Name alternateHostname).Value

                if ($config) {
                        $compliant = $true
                    } else {
                        $compliant = $false
                    }

                [pscustomobject] @{
                    Id              = "V-76883"
                    ComputerName    = $env:COMPUTERNAME
                    SiteName        = $webname
                    Hostname        = $config
                    Compliant       = $compliant
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
