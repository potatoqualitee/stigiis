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

        if ($PSVersionTable.PSVersion -ge "5.0") {

            Get-Package
        }

        else {

        $Keys = '','\Wow6432Node'

            foreach ($Key in $keys) {
                try {

                    $Apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
                }
                catch {

                    Continue
                }

                foreach ($App in $Apps) {

                    $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                    $Name = $Program.GetValue('DisplayName')

                    if ($Name -and $Name -match $NameRegex) {

                        [pscustomobject]@{
                            Computername = $Computer
                            Software = $Name
                            Version = $Program.GetValue('DisplayVersion')
                            Publisher = $Program.GetValue('Publisher')
                            InstallDate = $Program.GetValue('InstallDate')
                            UninstallString = $Program.GetValue('UninstallString')
                            Bits = $(if ($Key -eq '\Wow6432Node') {'64'} else {'32'})
                            Path = $Program.name
                        }
                    }
                }
            }
        }
    }
}
