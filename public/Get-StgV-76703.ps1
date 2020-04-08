function Get-StgV-76703 {
<#
    .SYNOPSIS
        Disable proxy settings for Application Request Routing feature for vulnerability 76703.

    .DESCRIPTION
        Disable proxy settings for Application Request Routing feature for vulnerability 76703.

    .NOTES
        Tags: V-76703
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT
#>

    param(

        [Parameter(DontShow)]
        [string]$WebPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($Webname in $WebNames) {

        try {

            #Disable proxy for Application Request Routing
            Set-WebConfigurationProperty -Location $WebPath -Filter "system.webServer/proxy" -Name "Enabled" -Value "False"

            $ProxyValue = Get-WebConfigurationProperty -PSPath $WebPath -Filter "system.webServer/proxy" -Name "Enabled"

            [pscustomobject] @{

                Vulnerability = "V-76703"
                Computername = $env:COMPUTERNAME
                PostConfigurationProxy = $ProxyValue
            }
        }

        catch {

            [pscustomobject] @{

                Vulnerability = "V-76703"
                Computername = $env:COMPUTERNAME
                PostConfigurationProxy = "N/A: Application Request Routing not available"
            }
        }
    }

}
