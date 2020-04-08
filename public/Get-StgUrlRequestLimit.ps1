function Get-StgUrlRequestLimit {
<#
    .SYNOPSIS
        Configure and verify URL Request Limit settings for vulnerability 76817.

    .DESCRIPTION
        Configure and verify URL Request Limit settings for vulnerability 76817.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76817
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
        $filterpath = "system.webServer/security/requestFiltering/requestLimits"
        $MaxUrl = 4096

        foreach($webname in $webnames) {

            $PreConfigMaxUrl = Get-WebConfigurationProperty -Filter $filterpath -Name MaxUrl

            Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name MaxUrl -Value $MaxUrl -Force

            $PostConfigurationMaxUrl = Get-WebConfigurationProperty -Filter $filterpath -Name MaxUrl

            [pscustomobject] @{
                Vulnerability = "V-76817"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfiugrationMaxUrl = $PreConfigMaxUrl.Value
                PostConfiugrationMaxUrl = $PostConfigurationMaxUrl.Value
                Compliant = if ($PostConfigurationMaxUrl.Value -le $MaxUrl) {
                    "Yes"
                } else {
                    "No: Value must be $MaxUrl or less"
                }
            }
        }
    }
}