function Get-StgSSLSetting {
    <#
    .SYNOPSIS
        Get site SSL settings for vulnerability 76679, 76779, & 76781.

    .DESCRIPTION
        Get site SSL settings for vulnerability 76679, 76779, & 76781.

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
        PS C:\> Get-StgSSLSetting -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgSSLSetting -ComputerName web01 -Credential ad\webadmin

        Logs into web01 as ad\webadmin and reports the necessary information

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
                $postflags = Get-WebConfigurationProperty -Location $webname -Filter "system.webserver/security/access" -Name SSLFlags

                #Post-configuration data results
                if ($postflags -eq "Ssl" ) {
                    $config = "SSL: Required | Client Certificates: Ignore"
                } elseif ($postflags -eq "Ssl,SslNegotiateCert" ) {
                    $config = "SSL: Required | Client Certificates: Accept"
                } elseif ($postflags -eq "Ssl,SslNegotiateCert,SslRequireCert" ) {
                    $config = "SSL: Required | Client Certificates: Require"
                } elseif ($postflags -eq "SslNegotiateCert" ) {
                    $config = "SSL: Not Required | Client Certificates: Accept"
                } elseif ($postflags -eq "SslNegotiateCert,SslRequireCert" ) {
                    $config = "SSL: Not Required | Client Certificates: Require"
                } else {
                    $config = "SSL: Not Required | Client Certificates: Ignore"
                }

                #Check SSL setting compliance
                if ($config -eq "SSL: Required | Client Certificates: Accept") {
                    $compliant = $true
                } elseif ($config -eq "SSL: Required | Client Certificates: Require") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id        = "V-76679", "V-76779", "V-76781"
                    SiteName  = $webname
                    Value     = $config
                    Compliant = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Value, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}
