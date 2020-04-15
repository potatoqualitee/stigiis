function Set-StgSSLSetting {
    <#
    .SYNOPSIS
        Check, configure, and verify site SSL settings for vulnerability 76679, 76779, & 76781.

    .DESCRIPTION
        Check, configure, and verify site SSL settings for vulnerability 76679, 76779, & 76781.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76679, V-76779, V-76781
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgSSLSetting -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgSSLSetting -ComputerName web01 -Credential ad\webadmin

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
            foreach ($webname in $webnames) {

                $filterpath = "system.webserver/security/access"
                Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList "unlock", "config", "-section:$filterpath" -Wait
                #Pre-configuration SSL values
                $preflags = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name SSLFlags

                if ($preflags -ne "Ssl,SslNegotiateCert,SslRequireCert" -or $preflags -ne "Ssl,SslNegotiateCert") {
                    #Set SSL requirements
                    Set-WebConfiguration -Location $webname -Filter "system.webserver/security/access" -Value "Ssl,SslNegotiateCert"
                }

                #Post-configuration SSL values
                $postflags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                #Pre-configuration data results
                $preconfig = @(
                    if ($preflags -eq "Ssl" ) {
                        "SSL: Required | Client Certificates: Ignore"
                    } elseif ($preflags -eq "Ssl,SslNegotiateCert" ) {
                        "SSL: Required | Client Certificates: Accept"
                    } elseif ($preflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($preflags -eq "SslNegotiateCert" ) {
                        "SSL: Not Required | Client Certificates: Accept"
                    } elseif ($preflags -eq "SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Not Required | Client Certificates: Require"
                    } else {
                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )

                #Post-configuration data results
                $postconfig = @(
                    if ($postflags -eq "Ssl" ) {
                        "SSL: Required | Client Certificates: Ignore"
                    } elseif ($postflags -eq "Ssl,SslNegotiateCert" ) {
                        "SSL: Required | Client Certificates: Accept"
                    } elseif ($postflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Required | Client Certificates: Require"
                    } elseif ($postflags -eq "SslNegotiateCert" ) {
                        "SSL: Not Required | Client Certificates: Accept"
                    } elseif ($postflags -eq "SslNegotiateCert,SslRequireCert" ) {
                        "SSL: Not Required | Client Certificates: Require"
                    } else {
                        "SSL: Not Required | Client Certificates: Ignore"
                    }
                )

                #Check SSL setting compliance
                $compliant = @(
                    if ($postconfig -eq "SSL: Required | Client Certificates: Accept") {
                        $true
                    } elseif ($postconfig -eq "SSL: Required | Client Certificates: Require") {
                        $true
                    } else {
                        $false
                    }
                )

                [pscustomobject] @{
                    Id        = "V-76679", "V-76779", "V-76781"
                    SiteName  = $webname
                    Before    = $preconfig
                    After     = $postconfig
                    Compliant = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

