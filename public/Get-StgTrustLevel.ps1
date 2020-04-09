function Get-StgTrustLevel {
<#
    .SYNOPSIS
        Configure and verify .NET Trust Level settings for vulnerability 76805.

    .DESCRIPTION
        Configure and verify .NET Trust Level settings for vulnerability 76805.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76805
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
            $filterpath = "system.web/trust"
            foreach($webname in $webnames) {

                $PreConfigTrustLevel = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level).Value

                if ($PostConfigTrustLevel -ne "Full" -or $PostConfigTrustLevel -ne "Medium" -or $PostConfigTrustLevel -ne "Low" -or $PostConfigTrustLevel -ne "Minimal") {

                    Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level -Value "Full"
                }

                $PostConfigTrustLevel = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level).Value

                [pscustomobject] @{

                    Id = "V-76805"
                    ComputerName = $env:ComputerName
                    SiteName = $webname
                    PreConfigTrustLevel = $PreConfigTrustLevel
                    PostConfigTrustLevel = $PreConfigTrustLevel
                    SuggestedTrustLevel = "Full or less"
                    Compliant = if ($PostConfigTrustLevel -eq "Full" -or $PostConfigTrustLevel -eq "Medium" -or $PostConfigTrustLevel -eq "Low" -or $PostConfigTrustLevel -eq "Minimal") {

                        $true
                    }

                    else {

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