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
            $filterpath = "system.web/trust"
            foreach ($webname in $webnames) {

                $preconfigTrustLevel = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level).Value

                if ($postconfigTrustLevel -ne "Full" -or $postconfigTrustLevel -ne "Medium" -or $postconfigTrustLevel -ne "Low" -or $postconfigTrustLevel -ne "Minimal") {
                    Set-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level -Value "Full"
                }
                $postconfigTrustLevel = (Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Level).Value

                if ($postconfigTrustLevel -eq "Full" -or $postconfigTrustLevel -eq "Medium" -or $postconfigTrustLevel -eq "Low" -or $postconfigTrustLevel -eq "Minimal") {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id                  = "V-76805"
                    ComputerName        = $env:COMPUTERNAME
                    SiteName            = $webname
                    Before              = $preconfigTrustLevel
                    After               = $preconfigTrustLevel
                    SuggestedTrustLevel = "Full or less"
                    Compliant           = $compliant
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, SiteName, Before, After, SuggestedTrustLevel, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}