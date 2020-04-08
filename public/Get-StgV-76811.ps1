function Get-StgV-76811 {
    <#
    .SYNOPSIS
        Configure and verify Anonymous Authentication settings for vulnerability 76811.

    .DESCRIPTION
        Configure and verify Anonymous Authentication settings for vulnerability 76811.

    .NOTES
        Tags: V-76811
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT
#>
    param(

        [Parameter(DontShow)]
        [string]$PSPath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webServer/security/authentication/anonymousAuthentication'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PreConfigAnonymousAuthentication = Get-WebConfigurationProperty -Filter $FilterPath -Name Enabled

    Set-WebConfigurationProperty -PSPath $PSPath -Filter $FilterPath -Name Enabled -Value "False"

    $PostConfigurationAnonymousAuthentication = Get-WebConfigurationProperty -Filter $FilterPath -Name Enabled

    [pscustomobject] @{

        Vulnerability = "V-76811"
        Computername = $env:COMPUTERNAME
        PreConfigAnonymousAuthentication = $PreConfigAnonymousAuthentication.Value
        PostConfigurationAnonymousAuthentication = $PostConfigurationAnonymousAuthentication.Value
        Compliant = if($PostConfigurationAnonymousAuthentication.Value -eq $false) {

            "Yes"
        }

        else {

            "No"
        }
    }

}
