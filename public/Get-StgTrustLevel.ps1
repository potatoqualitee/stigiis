function Get-StgTrustLevel {
<#
    .SYNOPSIS
    Configure and verify .NET Trust Level settings for vulnerability 76805.

    .DESCRIPTION
    Configure and verify .NET Trust Level settings for vulnerability 76805.

    .NOTES
        Tags: V-76805
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
        $filterpath = 'system.web/trust'



        foreach($webname in $webnames) {

            $PreConfigTrustLevel = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level).Value

            if ($PostConfigTrustLevel -ne "Full" -or $PostConfigTrustLevel -ne "Medium" -or $PostConfigTrustLevel -ne "Low" -or $PostConfigTrustLevel -ne "Minimal") {

                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level -Value "Full"
            }

            $PostConfigTrustLevel = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level).Value

            [pscustomobject] @{

                Vulnerability = "V-76805"
                Computername = $env:COMPUTERNAME
                SiteName = $webname
                PreConfigTrustLevel = $PreConfigTrustLevel
                PostConfigTrustLevel = $PreConfigTrustLevel
                SuggestedTrustLevel = "Full or less"
                Compliant = if ($PostConfigTrustLevel -eq "Full" -or $PostConfigTrustLevel -eq "Medium" -or $PostConfigTrustLevel -eq "Low" -or $PostConfigTrustLevel -eq "Minimal") {

                    "Yes"
                }

                else {

                    "No"
                }
            }
        }
    }
}