function Uninstall-StgPrintService {
    <#
    .SYNOPSIS
        Configure and verify Print Services settings for vulnerability 76753.

    .DESCRIPTION
        Configure and verify Print Services settings for vulnerability 76753.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76753
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Uninstall-StgPrintService -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Uninstall-StgPrintService -ComputerName web01 -Credential ad\webadmin

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
            $printservices = @("Print-Services", "Print-Internet")

            if ($printfeatures) {
                $null = Get-WindowsFeature -Name $PrintService | Uninstall-WindowsFeature
            }

            $printfeatures = Get-WindowsFeature -Name $printservices

            if ($printfeatures.InstallState -eq "Available") {
                $compliant = $true
                $notes = $null
            } else {
                $compliant = $false
                $notes = "Remove $($printfeatures.Name) Windows Feature"
            }

            foreach ($Feature in $printfeatures) {
                [pscustomobject] @{
                    Id           = "V-76753"
                    ComputerName = $env:COMPUTERNAME
                    Feature      = $Feature.Name
                    InstallState = $Feature.InstallState
                    Compliant    = $compliant
                    Notes        = $notes
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Feature, InstallState, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

