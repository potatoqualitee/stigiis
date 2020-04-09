function Get-StgSessionStateCookie {
<#
    .SYNOPSIS
        Configure and verify cookieLess & regenerateExpiredSessionID properties for vulnerability 76725, 76727, & 76777.

    .DESCRIPTION
        Configure and verify cookieLess & regenerateExpiredSessionID properties for vulnerability 76725, 76727, & 76777.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76725, V-76727, V-76777
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
            $filterpath = "system.web/sessionState"
            foreach($webname in $webnames) {

                $PreCookieConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name CookieLess
                $PreSessionConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name RegenerateExpiredSessionID
                $PreTimeoutConfig = Get-WebConfigurationProperty -Location $webname -Filter "/system.webserver/asp/session" -Name Timeout

                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name CookieLess -Value "UseCookies"
                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name RegenerateExpiredSessionID -Value "True"
                Set-WebConfigurationProperty -Location $webname -Filter "system.webServer/asp/session" -Name TimeOut -Value "00:20:00"

                $PostCookieConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name CookieLess
                $PostSessionConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name RegenerateExpiredSessionID
                $PostTimeoutConfig = Get-WebConfigurationProperty -Location $webname -Filter "/system.webserver/asp/session" -Name Timeout

                [pscustomobject] @{
                    Vulnerability = "V-76725, V-76727, V-76777"
                    ComputerName = $env:ComputerName
                    SiteName = $webname
                    PreConfigCookiesLess = $PreCookieConfig
                    PreConfigSessionID = $PreSessionConfig.Value
                    PreConfigTimeout = $PreTimeoutConfig.Value
                    PostConfigurationCookiesLess = $PostCookieConfig
                    PostConfigurationSessionID = $PostSessionConfig.Value
                    PostConfigurationTimeout = $PreTimeoutConfig.Value
                    Compliant = if ($PostCookieConfig -eq "UseCookies" -and $PostSessionConfig.Value -eq "True" -and $PostTimeoutConfig.Value -eq "00:20:00") {

                        "Yes"
                    } else {

                        "No"
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