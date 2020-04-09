function Get-StgCompression {
<#
    .SYNOPSIS
        Configure and verify HTTP Cookies and Session Compression settings for vulnerability 76859.

    .DESCRIPTION
        Configure and verify HTTP Cookies and Session Compression settings for vulnerability 76859.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76859
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
        $pspath = "MACHINE/WEBROOT"
        $filerpathCookies = "system.web/httpCookies"
        $filerpathCompression = "system.web/sessionState"

        Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

        $PreConfigCookies = Get-WebConfigurationProperty -PSPath $pspath -Filter $filerpathCookies -Name requireSSL
        $PreConfigCompression = Get-WebConfigurationProperty -PSPath $pspath -Filter $filerpathCompression -Name compressionEnabled

        Set-WebConfigurationProperty -PSPath $pspath -Filter $filerpathCookies -Name requireSSL -Value "True"
        Set-WebConfigurationProperty -PSPath $pspath -Filter $filerpathCompression -Name compressionEnabled -Value "False"

        $PostConfigCookies = Get-WebConfigurationProperty -PSPath $pspath -Filter $filerpathCookies -Name requireSSL
        $PostConfigCompression = Get-WebConfigurationProperty -PSPath $pspath -Filter $filerpathCompression -Name compressionEnabled

        [pscustomobject] @{
            Vulnerability = "V-76859"
            Computername = $env:COMPUTERNAME
            Sitename = $env:COMPUTERNAME
            PreConfigCookiesSSL = $PreConfigCookies.Value
            PostConfigCookiesSSL = $PostConfigCookies.Value
            PreConfigCompressionEnabled = $PreConfigCompression.Value
            PostConfigCompressionEnabled = $PostConfigCompression.Value
            Compliant = if ($PostConfigCookies.Value -eq $true -and $PostConfigCompression.Value -eq $false) {
                "Yes"
            } else {
                "No"
            }
        }
    }
}