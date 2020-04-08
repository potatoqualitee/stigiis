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
        $filterpath = 'system.web/machineKey'



        $PreConfigValidation = Get-WebConfigurationProperty -Filter $filterpath -Name Validation
        $PreConfigEncryption = Get-WebConfigurationProperty -Filter $filterpath -Name Decryption

        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter $filterpath -Name "Validation" -Value "HMACSHA256"
        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter $filterpath -Name "Decryption" -Value "Auto"

        $PostConfigurationValidation = Get-WebConfigurationProperty -Filter $filterpath -Name Validation
        $PostConfigurationEncryption = Get-WebConfigurationProperty -Filter $filterpath -Name Decryption

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