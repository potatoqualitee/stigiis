function Get-StgAuthRule {
<#
    .SYNOPSIS
        Configure and verify Authorization Rules settings for vulnerability 76771.

    .DESCRIPTION
        Configure and verify Authorization Rules settings for vulnerability 76771.

    .NOTES
        Tags: V-76771
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
        $FilterPath = 'system.web/authorization/allow'
        $Settings = "[@roles='' and @users='*' and @verbs='']"

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        $PreConfigUsers = Get-WebConfigurationProperty -Filter $FilterPath -Name Users

        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "$($FilterPath)$($Settings)" -Name Users -Value "Administrators"
        Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "system.web/authorization" -Name "." -Value @{users='?'} -Type deny

        $PostConfigurationUsers = Get-WebConfigurationProperty -Filter $FilterPath -Name Users

        [pscustomobject] @{
            Vulnerability = "V-76771"
            Computername = $env:COMPUTERNAME
            PreConfigAuthorizedUsers = $PreConfigUsers.Value
            PostConfigurationAuthorizedUsers = $PostConfigurationUsers.Value
            Compliant = if ($PostConfigurationUsers.Value -eq "Administrators") {
                "Yes"
            } else {
                "No"
            }
        }
    }
}