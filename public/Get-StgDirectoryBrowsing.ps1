function Get-StgDirectoryBrowsing {
<#
.SYNOPSIS
    Configure and verify Directory Browsing properties for vulnerability 76733 & 76829.

.DESCRIPTION
    Configure and verify Directory Browsing properties for vulnerability 76733 & 76829.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76733, V-76829
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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/directoryBrowse"

            foreach($webname in $webnames) {

                $PreDirectoryBrowsing = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled

                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled -Value "False"

                $PostDirectoryBrowsing = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled

                [pscustomobject] @{
                    Id = "V-76829"
                    ComputerName = $env:ComputerName
                    SiteName = $webname
                    PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
                    PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
                    Compliant = if ($PostDirectoryBrowsing.Value -eq $false) {
                        $true
                    } else {
                        $false
                    }
                }
            }

            $PreDirectoryBrowsing = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $filterpath -Name Enabled

            Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled -Value "False"

            $PostDirectoryBrowsing = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $filterpath -Name Enabled

            [pscustomobject] @{
                Id = "V-76733"
                ComputerName = $env:ComputerName
                SiteName = $env:ComputerName
                PreConfigBrowsingEnabled = $PreDirectoryBrowsing.Value
                PostConfigurationBrowsingEnabled = $PostDirectoryBrowsing.Value
                Compliant = if ($PostDirectoryBrowsing.Value -eq $false) {
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
                    Select-DefaultView -Property Id, ComputerName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}