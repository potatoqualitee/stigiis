function Get-StgV-76715 {
<#
    .SYNOPSIS
        Report certificates for vulnerability 76713.

    .DESCRIPTION
        Report certificates for vulnerability 76713.

    .NOTES
        Tags: V-76715
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>

    param(

        [Parameter(ValuefromPipeline=$true)]
        [string]$Server = $env:COMPUTERNAME
    )

    Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"

    $RO = [System.Security.Cryptography.X509Certificates.OpenFlags]"ReadOnly"
    $LM = [System.Security.Cryptography.X509Certificates.StoreLocation]"LocalMachine"

    $Stores = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$Server\root",$LM)
    $Stores.Open($RO)
    $Certs = $Stores.Certificates

    foreach($Cert in $Certs) {

        [pscustomobject] @{

            Server = $Server
            DNS = $Cert.DNSNameList
            ExpirationDate = $Cert.NotAfter
            Version = $Cert.Version
            HasPrivateKey = $Cert.HasPrivateKey
        }
    }

}
