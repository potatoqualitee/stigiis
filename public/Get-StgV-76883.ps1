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
        $pspath = 'MACHINE/WEBROOT/APPHOST'
        $webnames = (Get-Website).Name
        $filterpath = 'system.webserver/serverRuntime'

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        foreach($webname in $webnames) {

            $PreConfigHostname = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name alternateHostname).Value

            if ([string]::IsNullOrWhiteSpace($PreConfigHostname)) {

                [string]$AlternateHostName = "$(($webname).Replace(' ','')).$((Get-CimInstance -ClassName Win32_ComputerSystem).Domain)"

                Set-WebConfigurationProperty -PSPath $pspath/$($webname) -Filter $filterpath -Name alternateHostname -Value $AlternateHostName
            }

            $PostConfigHostname = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name alternateHostname).Value

            [pscustomobject] @{
                Vulnerability = "V-76883"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigHostname = $PreConfigHostname
                PostConfigHostname = $PostConfigHostname
                Compliant = if (-not ([string]::IsNullOrWhiteSpace($PostConfigHostname))) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}