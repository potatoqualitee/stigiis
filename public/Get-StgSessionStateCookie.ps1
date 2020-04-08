function Get-StgSessionStateCookie {
<#
    .SYNOPSIS
        Configure and verify cookieLess & regenerateExpiredSessionID properties for vulnerability 76725, 76727, & 76777.

    .DESCRIPTION
        Configure and verify cookieLess & regenerateExpiredSessionID properties for vulnerability 76725, 76727, & 76777.

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
    }
    process {
        $WebNames = (Get-Website).Name
        $FilterPath = 'system.web/sessionState'

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        foreach($WebName in $WebNames) {

            $PreCookieConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name CookieLess
            $PreSessionConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name RegenerateExpiredSessionID
            $PreTimeoutConfig = Get-WebConfigurationProperty -Location $WebName -Filter "/system.webserver/asp/session" -Name Timeout

            Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name CookieLess -Value 'UseCookies'
            Set-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name RegenerateExpiredSessionID -Value 'True'
            Set-WebConfigurationProperty -Location $Webname -Filter 'system.webServer/asp/session' -Name TimeOut -Value '00:20:00'

            $PostCookieConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name CookieLess
            $PostSessionConfig = Get-WebConfigurationProperty -Location $Webname -Filter $FilterPath -Name RegenerateExpiredSessionID
            $PostTimeoutConfig = Get-WebConfigurationProperty -Location $WebName -Filter "/system.webserver/asp/session" -Name Timeout

            [pscustomobject] @{
                Vulnerability = "V-76725, V-76727, V-76777"
                Computername = $env:COMPUTERNAME
                SiteName = $WebName
                PreConfigCookiesLess = $PreCookieConfig
                PreConfigSessionID = $PreSessionConfig.Value
                PreConfigTimeout = $PreTimeoutConfig.Value
                PostConfigurationCookiesLess = $PostCookieConfig
                PostConfigurationSessionID = $PostSessionConfig.Value
                PostConfigurationTimeout = $PreTimeoutConfig.Value
                Compliant = if ($PostCookieConfig -eq 'UseCookies' -and $PostSessionConfig.Value -eq "True" -and $PostTimeoutConfig.Value -eq '00:20:00') {

                    "Yes"
                } else {

                    "No"
                }
            }
        }
    }
}