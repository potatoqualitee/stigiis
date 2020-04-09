function Get-StgEncryptionValidation {
<#
    .SYNOPSIS
        Configure and verify Validation and Encryption properties for vulnerability 76731.

    .DESCRIPTION
        Configure and verify Validation and Encryption properties for vulnerability 76731.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

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
        $scriptblock = {
            $filterpath = "system.web/machineKey"
            $PreConfigValidation = Get-WebConfigurationProperty -Filter $filterpath -Name Validation
            $PreConfigEncryption = Get-WebConfigurationProperty -Filter $filterpath -Name Decryption

            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter $filterpath -Name "Validation" -Value "HMACSHA256"
            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter $filterpath -Name "Decryption" -Value "Auto"

            $PostConfigurationValidation = Get-WebConfigurationProperty -Filter $filterpath -Name Validation
            $PostConfigurationEncryption = Get-WebConfigurationProperty -Filter $filterpath -Name Decryption

            [pscustomobject] @{
                Id = "V-76731"
                ComputerName = $env:ComputerName
                PreConfigValidation = $PreConfigValidation
                PreConfigEncryption = $PreConfigEncryption.Value
                PostConfigurationValidation = $PostConfigurationValidation
                PostConfigurationEncryption = $PostConfigurationEncryption.Value
                Compliant = if ($PostConfigurationValidation -eq "HMACSHA256" -and $PostConfigurationEncryption.Value -eq "Auto") {
                    $true
                } else {
                    $false
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property ComputerName, Id, Sitename, Hostname, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}