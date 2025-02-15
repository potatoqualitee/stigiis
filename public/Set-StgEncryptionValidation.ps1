function Set-StgEncryptionValidation {
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

    .EXAMPLE
        PS C:\> Set-StgEncryptionValidation -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgEncryptionValidation -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and updates the necessary setting

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
            Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:$filterpath" -Wait

            $preconfigValidation = Get-WebConfigurationProperty -Filter $filterpath -Name Validation
            $preconfigEncryption = Get-WebConfigurationProperty -Filter $filterpath -Name Decryption

            $null = Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter $filterpath -Name "Validation" -Value "HMACSHA256"
            $null = Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT" -Filter $filterpath -Name "Decryption" -Value "Auto"

            $postconfigValidation = Get-WebConfigurationProperty -Filter $filterpath -Name Validation
            $postconfigEncryption = Get-WebConfigurationProperty -Filter $filterpath -Name Decryption

            if ($postconfigValidation -eq "HMACSHA256" -and $postconfigEncryption.Value -eq "Auto") {
                $compliant = $true
            } else {
                $compliant = $false
            }

            [pscustomobject] @{
                Id               = "V-76731"
                ComputerName     = $env:COMPUTERNAME
                BeforeValidation = $preconfigValidation
                BeforeEncryption = $preconfigEncryption.Value
                AfterValidation  = $postconfigValidation
                AfterEncryption  = $postconfigEncryption.Value
                Compliant        = $compliant
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, BeforeEncryption, AfterEncryption, BeforeValidation, AfterValidation, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

