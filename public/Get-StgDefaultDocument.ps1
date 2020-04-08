function Get-StgDefaultDocument {
<#
    .SYNOPSIS
        Configure and verify Default Document settings for vulnerability 76831.

    .DESCRIPTION
        Configure and verify Default Document settings for vulnerability 76831.

    .NOTES
        Tags: V-76831
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
        $filterpath = 'system.webServer/defaultDocument'
        foreach($webname in $webnames) {

            $PreConfigDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled

            if ($PreConfigDefaultDocumentEnabled -eq $false) {

                Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name Enabled -Value "True"
            }

            $PreConfigDefaultDocumentFiles = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Files

            if ($PreConfigDefaultDocumentFiles.Count -eq 0) {

                Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value='Default.aspx'}
            }

            $PostConfigurationDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled
            $PostConfigurationDefaultDocumentFiles = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Files

            [pscustomobject] @{
                Vulnerability = "V-76831"
                Computername = $env:COMPUTERNAME
                Sitename = $webname
                PreConfigDefaultDocumentEnabled = $PreConfigDefaultDocumentEnabled.Value
                PreConfigDefaultDocumentFiles = $PreConfigDefaultDocumentFiles.Count
                PostConfigurationDefaultDocumentEnabled = $PostConfigurationDefaultDocumentEnabled.Value
                PostConfigurationDefaultDocumentFiles = $PostConfigurationDefaultDocumentFiles.Count
                Compliant = if ($PostConfigurationDefaultDocumentEnabled.Value -eq $true -and $PostConfigurationDefaultDocumentFiles.Count -gt 0) {
                    "Yes"
                } else {
                    "No"
                }

            }
        }
    }
}