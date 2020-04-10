function Get-StgV-76715 {
<#
    .SYNOPSIS
        Report certificates for vulnerability 76713.

    .DESCRIPTION
        Report certificates for vulnerability 76713.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76715
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
            $RO = [System.Security.Cryptography.X509Certificates.OpenFlags]"ReadOnly"
            $LM = [System.Security.Cryptography.X509Certificates.StoreLocation]"LocalMachine"

            $Stores = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$env:COMPUTERNAME\root",$LM)
            $Stores.Open($RO)
            $Certs = $Stores.Certificates

            foreach($Cert in $Certs) {
                [pscustomobject] @{
                    ComputerName = $env:COMPUTERNAME
                    DNS = $Cert.DNSNameList
                    ExpirationDate = $Cert.NotAfter
                    Version = $Cert.Version
                    HasPrivateKey = $Cert.HasPrivateKey
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
