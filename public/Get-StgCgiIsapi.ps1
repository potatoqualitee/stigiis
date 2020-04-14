function Get-StgCgiIsapi {
    <#
    .SYNOPSIS
        Configure and verify CGI and ISAPI module settings for vulnerability 76769.

    .DESCRIPTION
        Configure and verify CGI and ISAPI module settings for vulnerability 76769.

        By allowing unspecified file extensions to execute, the web servers attack surface is significantly increased. This increased risk can be reduced by only allowing specific ISAPI extensions or CGI extensions to run on the web server.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76769
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgCgiIsapi -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgCgiIsapi -ComputerName web01 -Credential ad\webadmin

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
            $Extensions = @(
                "notListedCgisAllowed",
                "notListedIsapisAllowed"
            )
            $filterpath = "system.webserver/security/isapiCgiRestriction"

            $preconfigCGIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedCgisAllowed"
            $preconfigISAPIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedIsapisAllowed"

            Set-WebConfigurationProperty -Filter $filterpath -Name notListedCgisAllowed -Value "False" -Force
            Set-WebConfigurationProperty -Filter $filterpath -Name notListedIsapisAllowed -Value "False" -Force

            $postconfigurationCGIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedCgisAllowed"
            $postconfigurationISAPIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedIsapisAllowed"

            if (-not $postconfigurationCGIExtension.Value -and -not $postconfigurationISAPIExtension.Value) {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id           = "V-76769"
                ComputerName = $env:COMPUTERNAME
                BeforeCGI    = $preconfigCGIExtension.Value
                BeforeISAPI  = $preconfigISAPIExtension.Value
                AfterCGI     = $postconfigurationCGIExtension.Value
                AfterISAPI   = $postconfigurationISAPIExtension.Value
                Compliant    = $compliant
                Notes        = "If auto configuration failed, this section may be locked. Configure manually."
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, BeforeCGI, BeforeISAPI, AfterCGI, AfterISAPI, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
