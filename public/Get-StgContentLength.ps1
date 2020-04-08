function Get-StgContentLength {
<#
    .SYNOPSIS
        Configure and verify Maximum Content Length settings for vulnerability 76819.

    .DESCRIPTION
        Configure and verify Maximum Content Length settings for vulnerability 76819.

    .NOTES
        Tags: V-76819
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
        $FilterPath = 'system.webServer/security/requestFiltering/requestLimits'
        $MaxContentLength = 30000000

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        foreach($WebName in $WebNames) {

            $PreConfigMaxContentLength = Get-WebConfigurationProperty -Filter $FilterPath -Name maxAllowedContentLength

            Set-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name maxAllowedContentLength -Value $MaxContentLength -Force

            $PostConfigurationMaxContentLength = Get-WebConfigurationProperty -Filter $FilterPath -Name maxAllowedContentLength

            [pscustomobject] @{
                Vulnerability = "V-76819"
                Computername = $env:COMPUTERNAME
                Sitename = $WebName
                PreConfiugrationMaxContentLength = $PreConfigMaxContentLength.Value
                PostConfiugrationMaxContentLength = $PostConfigurationMaxContentLength.Value
                Compliant = if ($PostConfigurationMaxContentLength.Value -le $MaxContentLength) {

                    "Yes"
                } else {
                    "No: Value must be $MaxContentLength or less"
                }
            }
        }
    }
}