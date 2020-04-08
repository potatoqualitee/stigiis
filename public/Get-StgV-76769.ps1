function Get-StgV-76769 {

    .NOTES
        Tags: V-76769
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

<#
.SYNOPSIS
    Configure and verify CGI and ISAPI module settings for vulnerability 76769.

.DESCRIPTION
    Configure and verify CGI and ISAPI module settings for vulnerability 76769.
#>
    param(

        [Parameter(DontShow)]
        $Extensions = @(

            "notListedCgisAllowed",
            "notListedIsapisAllowed"
        ),

        [Parameter(DontShow)]
        $FilterPath = 'system.webserver/security/isapiCgiRestriction'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PreConfigCGIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedCgisAllowed"
    $PreConfigISAPIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedIsapisAllowed"

    Set-WebConfigurationProperty -Filter $FilterPath -Name notListedCgisAllowed -Value "False" -Force
    Set-WebConfigurationProperty -Filter $FilterPath -Name notListedIsapisAllowed -Value "False" -Force

    $PostConfigurationCGIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedCgisAllowed"
    $PostConfigurationISAPIExtension = Get-WebConfigurationProperty -Filter $FilterPath -Name "notListedIsapisAllowed"

    [pscustomobject] @{

        Vulnerability = "V-76769"
        Computername = $env:COMPUTERNAME
        PreConfigCGI = $PostConfigurationCGIExtension.Value
        PreConfigISAPI = $PostConfigurationISAPIExtension.Value
        PostConfigurationCGI = $PostConfigurationCGIExtension.Value
        PostConfigurationISAPI = $PostConfigurationISAPIExtension.Value
        Compliant = if($PostConfigurationCGIExtension.Value -eq $false -and $PostConfigurationISAPIExtension.Value -eq $false) {

            "Yes"
        }

        else {

            "No: If auto configuration failed, this section may be locked. Configure manually."
        }
    }

}
