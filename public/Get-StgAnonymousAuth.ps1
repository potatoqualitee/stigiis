function Get-StgAnonymousAuth {
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
        $filterpath = 'system.webServer/security/authentication/anonymousAuthentication'



        $PreConfigAnonymousAuthentication = Get-WebConfigurationProperty -Filter $filterpath -Name Enabled

        Set-WebConfigurationProperty -PSPath $pspath -Filter $filterpath -Name Enabled -Value "False"

        $PostConfigurationAnonymousAuthentication = Get-WebConfigurationProperty -Filter $filterpath -Name Enabled

        [pscustomobject] @{
            Vulnerability = "V-76811"
            Computername = $env:COMPUTERNAME
            PreConfigAnonymousAuthentication = $PreConfigAnonymousAuthentication.Value
            PostConfigurationAnonymousAuthentication = $PostConfigurationAnonymousAuthentication.Value
            Compliant = if ($PostConfigurationAnonymousAuthentication.Value -eq $false) {
                "Yes"
            } else {
                "No"
            }
        }
    }
}