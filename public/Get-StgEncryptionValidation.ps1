function Get-StgEncryptionValidation {
<#
    .SYNOPSIS
        Configure and verify Validation and Encryption properties for vulnerability 76731.

    .DESCRIPTION
        Configure and verify Validation and Encryption properties for vulnerability 76731.

    .NOTES
        Tags: V-76731
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
        $FilterPath = 'system.web/machineKey'

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        $PreConfigValidation = Get-WebConfigurationProperty -Filter $FilterPath -Name Validation
        $PreConfigEncryption = Get-WebConfigurationProperty -Filter $FilterPath -Name Decryption

        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter $FilterPath -Name "Validation" -Value "HMACSHA256"
        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter $FilterPath -Name "Decryption" -Value "Auto"

        $PostConfigurationValidation = Get-WebConfigurationProperty -Filter $FilterPath -Name Validation
        $PostConfigurationEncryption = Get-WebConfigurationProperty -Filter $FilterPath -Name Decryption

        [pscustomobject] @{
            Vulnerability = "V-76731"
            Computername = $env:COMPUTERNAME
            PreConfigValidation = $PreConfigValidation
            PreConfigEncryption = $PreConfigEncryption.Value
            PostConfigurationValidation = $PostConfigurationValidation
            PostConfigurationEncryption = $PostConfigurationEncryption.Value
            Compliant = if ($PostConfigurationValidation -eq 'HMACSHA256' -and $PostConfigurationEncryption.Value -eq 'Auto') {
                "Yes"
            } else {
                "No"
            }
        }
    }
}