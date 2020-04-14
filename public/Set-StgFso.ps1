function Set-StgFso {
    <#
    .SYNOPSIS
        Verify File System Component settings for vulnerability 76767.

    .DESCRIPTION
        Verify File System Component settings for vulnerability 76767.

        Some Component Object Model (COM) components are not required for most applications and should be removed if possible. Most notably, consider disabling the File System Object component; however, this will also remove the Dictionary object. Be aware some programs may require this component (e.g., Commerce Server), so it is highly recommended this be tested completely before implementing on the production web server.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76767
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Set-StgFso -ComputerName web01

        Updates specific setting to be compliant on web01

    .EXAMPLE
        PS C:\> Set-StgFso -ComputerName web01 -Credential ad\webadmin

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
            $FSOKey = "HKCR:\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"
            New-PSDrive -PSProvider Registry -root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

            $ComponentEnabled = if (Test-Path $FSOKey) {
                "Enabled"
            } else {
                "Disabled"
            }

            if (Test-Path $FSOKey) {
                $compliant = $false
                $notes = "Key exists. If component is NOT required for operations, run: regsvr32 scrrun.dll /u to unregister this library. Note: If the File System Object component is required for operations and has supporting documentation signed by the ISSO, this is not a finding."
            } else {
                $compliant = $true
                $notes = $null
            }

            [pscustomobject] @{
                Id           = "V-76767"
                ComputerName = $env:COMPUTERNAME
                Key          = $FSOKey
                Value        = $ComponentEnabled
                Compliant    = $compliant
                Notes        = $notes
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-DefaultView -Property Id, ComputerName, Key, Value, Compliant, Notes |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}

