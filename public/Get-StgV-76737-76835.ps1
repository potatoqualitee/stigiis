function Get-StgV-76737-76835 {
<#
    .SYNOPSIS
        Configure and verify Directory Browsing properties for vulnerability 76737 & 76835.

    .DESCRIPTION
        Configure and verify Directory Browsing properties for vulnerability 76737 & 76835.

    .NOTES
        Tags: V-76737, V-76835
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        $FilterPath = 'system.webServer/httpErrors'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($WebName in $Webnames) {

        $PreErrorMode = Get-WebConfigurationProperty -Filter $FilterPath -Name ErrorMode

        Set-WebConfigurationProperty -Filter $FilterPath -Name ErrorMode -Value "DetailedLocalOnly"

        $PostErrorMode = Get-WebConfigurationProperty -Filter $FilterPath -Name ErrorMode

        [pscustomobject] @{

            Vulnerability = "V-76733, V-76835"
            Computername = $env:COMPUTERNAME
            SiteName = $WebName
            PreConfigBrowsingEnabled = $PreErrorMode
            PostConfigurationBrowsingEnabled = $PostErrorMode
            Compliant = if($PostErrorMode -eq "DetailedLocalOnly") {

                "Yes"
            }

            else {

                "No"
            }
        }
    }

}
