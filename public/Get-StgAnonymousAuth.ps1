function Get-StgAnonymousAuth {
    <#
    .SYNOPSIS
        Configure and verify Anonymous Authentication settings for vulnerability 76811.

    .DESCRIPTION
        Configure and verify Anonymous Authentication settings for vulnerability 76811.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76811
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
            $pspath = "MACHINE/WEBROOT/APPHOST"
            $filterpath = "system.webServer/security/authentication/anonymousAuthentication"
            $PreConfigAnonymousAuthentication = Get-WebConfigurationProperty -Filter $filterpath -Name Enabled

            Set-WebConfigurationProperty -PSPath $pspath -Filter $filterpath -Name Enabled -Value "False"

            $PostConfigurationAnonymousAuthentication = Get-WebConfigurationProperty -Filter $filterpath -Name Enabled

            [pscustomobject] @{
                Vulnerability = "V-76811"
                ComputerName = $env:ComputerName
                PreConfigAnonymousAuthentication = $PreConfigAnonymousAuthentication.Value
                PostConfigurationAnonymousAuthentication = $PostConfigurationAnonymousAuthentication.Value
                Compliant = if ($PostConfigurationAnonymousAuthentication.Value -eq $false) {
                    "Yes"
                } else {
                    "No"
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