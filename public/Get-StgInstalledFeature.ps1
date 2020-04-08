function Get-StgInstalledFeature {
<#
    .SYNOPSIS
        Report installed Windows Features for vulnerability 76709.

    .DESCRIPTION
        Report installed Windows Features for vulnerability 76709.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76709
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
        Write-PSFMessage -Level Verbose -Message "Reporting STIG Settings for $($MyInvocation.MyCommand)"

        #Get all installed Windows Features
        $Features = Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed' -or $_.InstallState -eq 'InstallPending'}

        foreach($Feature in $Features) {
            [pscustomobject] @{
                Computername = $env:COMPUTERNAME
                Name = $Feature.Name
                InstallState = $Feature.InstallState
            }
        }
    }
}