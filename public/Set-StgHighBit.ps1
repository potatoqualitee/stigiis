function Set-StgHighBit {
    <#
    .SYNOPSIS
        Configure and verify Allow High-Bit Characters settings for vulnerability 76823.

    .DESCRIPTION
        Configure and verify Allow High-Bit Characters settings for vulnerability 76823.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76823
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgHighBit -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgHighBit -ComputerName web01 -Credential ad\webadmin

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
            $webnames = (Get-Website).Name
            $filterpath = "system.webServer/security/requestFiltering"

            foreach ($webname in $webnames) {
                $preconfigHighBit = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowHighBitCharacters

                Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name "allowHighBitCharacters" -Value "False"

                $postconfigurationHighBit = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name allowHighBitCharacters

                if (-not $postconfigurationHighBit.Value) {
                    $compliant = $true
                } else {
                    $compliant = $false
                }

                [pscustomobject] @{
                    Id           = "V-76823"
                    ComputerName = $env:COMPUTERNAME
                    SiteName     = $webname
                    Before       = $preconfigHighBit.Value
                    After        = $postconfigurationHighBit.Value
                    Compliant    = $compliant
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
