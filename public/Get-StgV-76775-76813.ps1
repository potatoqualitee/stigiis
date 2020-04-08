function Get-StgV-76775-76813 {

    .NOTES
        Tags: V-76775, V-76813
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

<#
.SYNOPSIS
   Configure and verify Session State Mode settings for vulnerability 76775 & 76813.

.DESCRIPTION
   Configure and verify Session State Mode settings for vulnerability 76775 & 76813.
#>
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.web/sessionState'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $PreConfigMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

    Set-WebConfigurationProperty -Filter $FilterPath -Name Mode -Value "InProc"

    $PostConfigurationMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

    [pscustomobject] @{

        Vulnerability = "V-76775"
        Computername = $env:COMPUTERNAME
        Sitename = $env:COMPUTERNAME
        PreConfigMode = $PreConfigMode
        PostConfigurationMode = $PostConfigurationMode
        Compliant = if($PostConfigurationMode -eq "InProc") {

            "Yes"
        }

        else {

            "No"
        }
    }

    foreach($Webname in $WebNames) {

        $PreConfigMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

        Set-WebConfigurationProperty -Filter $FilterPath -Name Mode -Value "InProc"

        $PostConfigurationMode = Get-WebConfigurationProperty -Filter $FilterPath -Name Mode

        [pscustomobject] @{

            Vulnerability = "V-76813"
            Computername = $env:COMPUTERNAME
            Sitename = $Webname
            PreConfigMode = $PreConfigMode
            PostConfigurationMode = $PostConfigurationMode
            Compliant = if($PostConfigurationMode -eq "InProc") {

                "Yes"
            }

            else {

                "No"
            }
        }
    }

}
