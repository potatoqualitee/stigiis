function Get-StgSessionSecurity {
<#
    .SYNOPSIS
        Configure and verify Session Security settings for vulnerability 76757 & 76855.

    .DESCRIPTION
        Configure and verify Session Security settings for vulnerability 76757 & 76855.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76757, V-76855
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
            $filterpath = "system.webServer/asp/session"
            $PreConfigSessionID = Get-WebConfigurationProperty -Filter $filterpath  -Name KeepSessionIdSecure

            Set-WebConfigurationProperty -Filter $filterpath -Name KeepSessionIdSecure -Value $true

            $PostConfigurationSessionID = Get-WebConfigurationProperty -Filter $filterpath  -Name KeepSessionIdSecure

            [pscustomobject] @{
                Id = "V-76757"
                ComputerName = $env:ComputerName
                Sitename = $env:ComputerName
                PreConfigSessionID = $PreConfigSessionID.Value
                PostConfigurationSessionID = $PostConfigurationSessionID.Value
                Compliant = if ($PostConfigurationSessionID.Value -eq "True") {
                    $true
                } else {
                    $false
                }
            }

            foreach($webname in $webname) {

                $PreConfigSessionID = Get-WebConfigurationProperty -Location $webname -Filter $filterpath  -Name KeepSessionIdSecure

                Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name KeepSessionIdSecure -Value $true

                $PostConfigurationSessionID = Get-WebConfigurationProperty -Location $webname -Filter $filterpath  -Name KeepSessionIdSecure

                [pscustomobject] @{
                    Id = "V-76855"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfigSessionID = $PreConfigSessionID.Value
                    PostConfigurationSessionID = $PostConfigurationSessionID.Value
                    Compliant = if ($PostConfigurationSessionID.Value -eq "True") {
                        $true
                    } else {
                        $false
                    }
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