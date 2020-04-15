function Set-StgSessionStateCookie {
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

    .EXAMPLE
        PS C:\> Set-StgSessionStateCookie -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgSessionStateCookie -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and updates the necessary setting

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
            Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:$filterpath" -Wait
            foreach ($webname in $webnames) {
                $preCookieConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name CookieLess
                $preSessionConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name RegenerateExpiredSessionID
                $preTimeoutConfig = Get-WebConfigurationProperty -Location $webname -Filter "/system.webserver/asp/session" -Name Timeout

                $null = Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name CookieLess -Value "UseCookies"
                $null = Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name RegenerateExpiredSessionID -Value "True"
                $null = Set-WebConfigurationProperty -Location $webname -Filter "system.webServer/asp/session" -Name TimeOut -Value "00:20:00"

                $postCookieConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name CookieLess
                $postSessionConfig = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name RegenerateExpiredSessionID
                $postTimeoutConfig = Get-WebConfigurationProperty -Location $webname -Filter "/system.webserver/asp/session" -Name Timeout

                if ($postCookieConfig -eq "UseCookies" -and $postSessionConfig.Value -eq "True" -and $postTimeoutConfig.Value -eq "00:20:00") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id                        = "V-76725", "V-76727", "V-76777"
                    ComputerName              = $env:COMPUTERNAME
                    SiteName                  = $webname
                    BeforeCookiesLess         = $preCookieConfig
                    BeforeSessionID           = $preSessionConfig.Value
                    BeforeTimeout             = $preTimeoutConfig.Value
                    AfterCookiesLess          = $postCookieConfig
                    AfterSessionID            = $postSessionConfig.Value
                    AfterConfigurationTimeout = $preTimeoutConfig.Value
                    Compliant                 = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, BeforeCookiesLess, BeforeSessionID, BeforeTimeout, AfterCookiesLess, AfterSessionID, AfterConfigurationTimeout, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

