function Get-StgV-76757-76855 {

    .NOTES
        Tags: V-76757, V-76855
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

<#
.SYNOPSIS
    Configure and verify Session Security settings for vulnerability 76757 & 76855.

.DESCRIPTION
    Configure and verify Session Security settings for vulnerability 76757 & 76855.
#>
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        $FilterPath = 'system.webServer/asp/session'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PreConfigSessionID = Get-WebConfigurationProperty -Filter $FilterPath  -Name KeepSessionIdSecure

    Set-WebConfigurationProperty -Filter $FilterPath -Name KeepSessionIdSecure -Value $true

    $PostConfigurationSessionID = Get-WebConfigurationProperty -Filter $FilterPath  -Name KeepSessionIdSecure

    [pscustomobject] @{

        Vulnerability = "V-76757"
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigSessionID = $PreConfigSessionID.Value
        PostConfigurationSessionID = $PostConfigurationSessionID.Value
        Compliant = if($PostConfigurationSessionID.Value -eq "True") {

            "Yes"
        }

        else {

            "No"
        }
    }

    foreach($WebName in $WebName) {

        $PreConfigSessionID = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath  -Name KeepSessionIdSecure

        Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name KeepSessionIdSecure -Value $true

        $PostConfigurationSessionID = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath  -Name KeepSessionIdSecure

        [pscustomobject] @{

            Vulnerability = "V-76855"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigSessionID = $PreConfigSessionID.Value
            PostConfigurationSessionID = $PostConfigurationSessionID.Value
            Compliant = if($PostConfigurationSessionID.Value -eq "True") {

                "Yes"
            }

            else {

                "No"
            }
        }
    }

}
