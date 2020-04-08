function Get-StgMaxQueryString {
<#
    .SYNOPSIS
        Configure and verify Maximum Query String settings for vulnerability 76821.

    .DESCRIPTION
        Configure and verify Maximum Query String settings for vulnerability 76821.

    .NOTES
        Tags: V-76821
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
        $filterpath = 'system.webServer/security/requestFiltering/requestLimits'
        [Int]$MaxQueryString = 2048



        foreach($webname in $webnames) {

            $PreConfigMaxQueryString = Get-WebConfigurationProperty -Filter $filterpath -Name maxQueryString

            Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name maxQueryString -Value $MaxQueryString -Force

            $PostConfigurationMaxQueryString = Get-WebConfigurationProperty -Filter $filterpath -Name maxQueryString

            [pscustomobject] @{
                Vulnerability = "V-76821"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfiugrationMaxQueryString = $PreConfigMaxQueryString.Value
                PostConfiugrationMaxQueryString = $PostConfigurationMaxQueryString.Value
                Compliant = if ($PostConfigurationMaxQueryString.Value -le $MaxQueryString) {
                    "Yes"
                } else {
                    "No: Value must be $MaxQueryString or less"
                }
            }
        }
    }
}