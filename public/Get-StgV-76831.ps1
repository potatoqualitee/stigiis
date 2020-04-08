function Get-StgV-76831 {
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
    param(

        [Parameter(DontShow)]
        $WebNames = (Get-Website).Name,

        [Parameter(DontShow)]
        [string]$FilterPath = 'system.webServer/defaultDocument'
    )

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    foreach($WebName in $WebNames) {

        $PreConfigDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled

        if ($PreConfigDefaultDocumentEnabled -eq $false) {

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter $FilterPath -Name Enabled -Value "True"
        }

        $PreConfigDefaultDocumentFiles = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Files

        if ($PreConfigDefaultDocumentFiles.Count -eq 0) {

            Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($WebName)" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value='Default.aspx'}
        }

        $PostConfigurationDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Enabled
        $PostConfigurationDefaultDocumentFiles = Get-WebConfigurationProperty -Location $WebName -Filter $FilterPath -Name Files

        [pscustomobject] @{

            Vulnerability = "V-76831"
            Computername = $env:COMPUTERNAME
            Sitename = $WebName
            PreConfigDefaultDocumentEnabled = $PreConfigDefaultDocumentEnabled.Value
            PreConfigDefaultDocumentFiles = $PreConfigDefaultDocumentFiles.Count
            PostConfigurationDefaultDocumentEnabled = $PostConfigurationDefaultDocumentEnabled.Value
            PostConfigurationDefaultDocumentFiles = $PostConfigurationDefaultDocumentFiles.Count
            Compliant = if ($PostConfigurationDefaultDocumentEnabled.Value -eq $true -and $PostConfigurationDefaultDocumentFiles.Count -gt 0) {

                "Yes"
            }

            else {

                "No"
            }

        }
    }

}
