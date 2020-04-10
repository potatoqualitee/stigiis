function Get-StgDoubleEscape {
<#
    .SYNOPSIS
        Configure and verify Allow Double Escaping settings for vulnerability 76825.

    .DESCRIPTION
        Configure and verify Allow Double Escaping settings for vulnerability 76825.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76825
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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/security/requestFiltering"

            foreach($webname in $webnames) {

                $preconfigDoubleEscaping = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowDoubleEscaping

                Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name allowDoubleEscaping -Value "False"

                $postconfigurationDoubleEscaping = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowDoubleEscaping

                [pscustomobject] @{
                    Id = "V-76825"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfigDoubleEscaping = $preconfigDoubleEscaping.Value
                    PostConfigurationDoubleEscaping = $postconfigurationDoubleEscaping.Value
                    Compliant = if ($postconfigurationDoubleEscaping.Value -eq $false) {
                        $true
                    } else {
                        $false
                    }
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}