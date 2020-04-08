function Get-StgV-76837 {
<#
.SYNOPSIS
    Configure and verify Debug Behavior settings for vulnerability 76837.

.DESCRIPTION
    Configure and verify Debug Behavior settings for vulnerability 76837.

    .NOTES
        Tags: V-76837
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
        $WebNames = (Get-Website).Name
        $FilterPath = 'system.web/compilation'


        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        foreach($WebName in $WebNames) {

            $PreConfigDebugBehavior = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Debug

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name Debug -Value "False"

            $PostConfigurationDebugBehavior = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Debug

            [pscustomobject] @{
                Vulnerability = "V-76837"
                Computername = $env:COMPUTERNAME
                Sitename = $WebName
                PreConfigDebugBehaviors = $PreConfigDebugBehavior.Value
                PostConfigurationDebugBehavior = $PostConfigurationDebugBehavior.Value
                Compliant = if ($PostConfigurationDebugBehavior.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
                }
            }
        }
    }
}