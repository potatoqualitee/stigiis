function Get-StgSessionSecurity {
<#
    .SYNOPSIS
        Configure and verify Session Security settings for vulnerability 76757 & 76855.

    .DESCRIPTION
        Configure and verify Session Security settings for vulnerability 76757 & 76855.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76757, V-76855
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
        $webnames = (Get-Website).Name
        $filterpath = "system.webServer/asp/session"



        $PreConfigSessionID = Get-WebConfigurationProperty -Filter $filterpath  -Name KeepSessionIdSecure

        Set-WebConfigurationProperty -Filter $filterpath -Name KeepSessionIdSecure -Value $true

        $PostConfigurationSessionID = Get-WebConfigurationProperty -Filter $filterpath  -Name KeepSessionIdSecure

        [pscustomobject] @{
            Vulnerability = "V-76757"
            Computername = $env:COMPUTERNAME
            Sitename = $env:COMPUTERNAME
            PreConfigSessionID = $PreConfigSessionID.Value
            PostConfigurationSessionID = $PostConfigurationSessionID.Value
            Compliant = if ($PostConfigurationSessionID.Value -eq "True") {
                "Yes"
            } else {
                "No"
            }
        }

        foreach($webname in $webname) {

            $PreConfigSessionID = Get-WebConfigurationProperty -Location $webname -Filter $filterpath  -Name KeepSessionIdSecure

            Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name KeepSessionIdSecure -Value $true

            $PostConfigurationSessionID = Get-WebConfigurationProperty -Location $webname -Filter $filterpath  -Name KeepSessionIdSecure

            [pscustomobject] @{
                Vulnerability = "V-76855"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigSessionID = $PreConfigSessionID.Value
                PostConfigurationSessionID = $PostConfigurationSessionID.Value
                Compliant = if ($PostConfigurationSessionID.Value -eq "True") {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}