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



            $PreConfigCGIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedCgisAllowed"
            $PreConfigISAPIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedIsapisAllowed"

            Set-WebConfigurationProperty -Filter $filterpath -Name notListedCgisAllowed -Value "False" -Force
            Set-WebConfigurationProperty -Filter $filterpath -Name notListedIsapisAllowed -Value "False" -Force

            $PostConfigurationCGIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedCgisAllowed"
            $PostConfigurationISAPIExtension = Get-WebConfigurationProperty -Filter $filterpath -Name "notListedIsapisAllowed"

            [pscustomobject] @{
                Id = "V-76769"
                ComputerName = $env:ComputerName
                PreConfigCGI = $PostConfigurationCGIExtension.Value
                PreConfigISAPI = $PostConfigurationISAPIExtension.Value
                PostConfigurationCGI = $PostConfigurationCGIExtension.Value
                PostConfigurationISAPI = $PostConfigurationISAPIExtension.Value
                Compliant = if ($PostConfigurationCGIExtension.Value -eq $false -and $PostConfigurationISAPIExtension.Value -eq $false) {
                    $true
                } else {
                    "No: If auto configuration failed, this section may be locked. Configure manually."
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