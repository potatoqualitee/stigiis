function Get-StgPrintService {
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
            $PrintPath = "$($env:windir)\web\printers"
            $PrintServices = @("Print-Services", "Print-Internet")
            $PrintFeatures = Get-WindowsFeature -Name $PrintServices

            foreach($Feature in $PrintFeatures) {
                [pscustomobject] @{
                    Vulnerability = "V-76753"
                    ComputerName = $env:ComputerName
                    Feature = $Feature.Name
                    InstallState = $Feature.InstallState
                    Compliant = if ($Feature.InstallState -eq "Available") {
                        "Yes"
                    } else {
                        "No: Remove $($Feature.Name) Windows Feature"
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