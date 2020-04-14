function Get-StgV-76737-76835 {
    <#
    .SYNOPSIS
        Configure and verify HTTP Error Detail properties for vulnerability 76737 & 76835.

    .DESCRIPTION
        Configure and verify HTTP Error Detail properties for vulnerability 76737 & 76835.

        HTTP error pages contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of HTTP error pages with full information to remote requesters exposes internal configuration information to potential attackers.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76737, V-76835
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgErrorDetail -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgErrorDetail -ComputerName web01 -Credential ad\webadmin

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
            $filterpath = "system.webServer/httpErrors"

            foreach ($webname in $webnames) {
                $preErrorMode = Get-WebConfigurationProperty -Filter $filterpath -Name ErrorMode
                Set-WebConfigurationProperty -Filter $filterpath -Name ErrorMode -Value "DetailedLocalOnly"
                $postErrorMode = Get-WebConfigurationProperty -Filter $filterpath -Name ErrorMode

                if ($postErrorMode -eq "DetailedLocalOnly") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76733, V-76835"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Value       = $preErrorMode
                    After        = $postErrorMode
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
