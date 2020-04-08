function Get-StgV-76883 {
<#
    .SYNOPSIS
        Configure and verify Alternate Hostname settings for vulnerability 76883.

    .DESCRIPTION
        Configure and verify Alternate Hostname settings for vulnerability 76883.

    .NOTES
        Tags: V-76883
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        [string]$PSpath = 'MACHINE/WEBROOT/APPHOST',

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webserver/serverRuntime'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($WebName in $WebNames) {

        $PreConfigHostname = (Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name alternateHostname).Value

        if([string]::IsNullOrWhiteSpace($PreConfigHostname)) {

            [string]$AlternateHostName = "$(($WebName).Replace(' ','')).$((Get-CimInstance -ClassName Win32_ComputerSystem).Domain)"

            Set-WebConfigurationProperty -PSPath $PSPath/$($WebName) -Filter $FilterPath -Name alternateHostname -Value $AlternateHostName
        }

        $PostConfigHostname = (Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name alternateHostname).Value

        [pscustomobject] @{

            Vulnerability = "V-76883"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigHostname = $PreConfigHostname
            PostConfigHostname = $PostConfigHostname
            Compliant = if(!([string]::IsNullOrWhiteSpace($PostConfigHostname))) {

                "Yes"
            }

            else {

                "No"
            }
        }
    }

}
