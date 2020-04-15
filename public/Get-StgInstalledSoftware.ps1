function Get-StgInstalledSoftware {
    <#
    .SYNOPSIS
        Report installed software for vulnerability 76701. Needs to be assessed manually.

    .DESCRIPTION
        Report installed software for vulnerability 76701. Needs to be assessed manually.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76701, Documentation
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

    .EXAMPLE
        PS C:\> Get-StgInstalledSoftware -ComputerName web01

        Gets required information from web01

    .EXAMPLE
        PS C:\> Get-StgInstalledSoftware -ComputerName web01 -Credential ad\webadmin

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
            $Keys = "", "\Wow6432Node"
            foreach ($Key in $keys) {
                try {
                    $apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
                } catch {
                    continue
                }

                foreach ($app in $apps) {
                    $program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                    $name = $program.GetValue("DisplayName")

                    if ($name -and $name -match $nameRegex) {
                        [pscustomobject]@{
                            ID              = "V-76701"
                            ComputerName    = $env:COMPUTERNAME
                            Software        = $name
                            Version         = $program.GetValue("DisplayVersion")
                            Publisher       = $program.GetValue("Publisher")
                            InstallDate     = $program.GetValue("InstallDate")
                            UninstallString = $program.GetValue("UninstallString")
                            Bits            = $(if ($Key -eq "\Wow6432Node") {"64"} else {"32"})
                            Path            = $program.name
                        }
                    }
                }
            }
        }
    }
    process {
        foreach ($computer in $ComputerName) {
            try {
                Invoke-Command2 -ComputerName $computer -Credential $credential -ScriptBlock $scriptblock |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}