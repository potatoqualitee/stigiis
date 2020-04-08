function Get-StgV-76859 {
<#
    .SYNOPSIS
        Configure and verify HTTP Cookies and Session Compression settings for vulnerability 76859.

    .DESCRIPTION
        Configure and verify HTTP Cookies and Session Compression settings for vulnerability 76859.

    .NOTES
        Tags: V-76859
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        $PSpath = 'MACHINE/WEBROOT',

        [Parameter(DontShow)]
        $FilterPathCookies = 'system.web/httpCookies',

        [Parameter(DontShow)]
        $FilterPathCompression = 'system.web/sessionState'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PreConfigCookies = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCookies -Name requireSSL
    $PreConfigCompression = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCompression -Name compressionEnabled

    Set-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCookies -Name requireSSL -Value "True"
    Set-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCompression -Name compressionEnabled -Value "False"

    $PostConfigCookies = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCookies -Name requireSSL
    $PostConfigCompression = Get-WebConfigurationProperty -PSPath $PSpath -Filter $FilterPathCompression -Name compressionEnabled


    [pscustomobject] @{

        Vulnerability = "V-76859"
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigCookiesSSL = $PreConfigCookies.Value
        PostConfigCookiesSSL = $PostConfigCookies.Value
        PreConfigCompressionEnabled = $PreConfigCompression.Value
        PostConfigCompressionEnabled = $PostConfigCompression.Value
        Compliant = if ($PostConfigCookies.Value -eq $true -and $PostConfigCompression.Value -eq $false) {

            "Yes"
        }

        else {

            "No"
        }
    }

}
