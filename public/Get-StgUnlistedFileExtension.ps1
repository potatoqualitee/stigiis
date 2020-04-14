function Get-StgUnlistedFileExtension {
    <#
    .SYNOPSIS
        Configure and verify Allow Unlisted File Extensions settings for vulnerability 76827.

    .DESCRIPTION
        Configure and verify Allow Unlisted File Extensions settings for vulnerability 76827.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76827
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT
        Caution: Commented out Set-ConfigurationProperty, this setting breaks the Web GUI for SolarWinds.

    .EXAMPLE
        PS C:\> Get-StgAltHostname -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgAltHostname -ComputerName web01 -Credential ad\webadmin

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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/security/requestFiltering/fileExtensions"

            foreach ($webname in $webnames) {
                $preconfigUnlistedExtensions = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowUnlisted
                Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name allowUnlisted -Value "False"
                $postconfigurationUnlistedExtensions = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowUnlisted

                if ($postconfigurationUnlistedExtensions.Value -eq $false) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76827"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Before       = $preconfigUnlistedExtensions.Value
                    After        = $postconfigurationUnlistedExtensions.Value
                    Compliant    = $compliant
                    Notes        = "Setting Allow Unlisted File Extensions to False breaks SolarWinds Web GUI"
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Before, After, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}