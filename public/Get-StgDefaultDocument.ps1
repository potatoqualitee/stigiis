function Get-StgDefaultDocument {
<#
    .SYNOPSIS
        Configure and verify Default Document settings for vulnerability 76831.

    .DESCRIPTION
        Configure and verify Default Document settings for vulnerability 76831.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76831
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
            $filterpath = "system.webServer/defaultDocument"
            foreach($webname in $webnames) {

                $preconfigDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled

                if ($preconfigDefaultDocumentEnabled -eq $false) {

                    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter $filterpath -Name Enabled -Value "True"
                }

                $preconfigDefaultDocumentFiles = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Files

                if ($preconfigDefaultDocumentFiles.Count -eq 0) {

                    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($webname)" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value="Default.aspx"}
                }

                $postconfigurationDefaultDocumentEnabled = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Enabled
                $postconfigurationDefaultDocumentFiles = Get-WebConfigurationProperty -Location $webname -Filter $filterpath -Name Files

                [pscustomobject] @{
                    Id = "V-76831"
                    ComputerName = $env:ComputerName
                    Sitename = $webname
                    PreConfigDefaultDocumentEnabled = $preconfigDefaultDocumentEnabled.Value
                    PreConfigDefaultDocumentFiles = $preconfigDefaultDocumentFiles.Count
                    PostConfigurationDefaultDocumentEnabled = $postconfigurationDefaultDocumentEnabled.Value
                    PostConfigurationDefaultDocumentFiles = $postconfigurationDefaultDocumentFiles.Count
                    Compliant = if ($postconfigurationDefaultDocumentEnabled.Value -eq $true -and $postconfigurationDefaultDocumentFiles.Count -gt 0) {
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
                    Select-DefaultView -Property Id, ComputerName, Before, After, Compliant |
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
            } catch {
                Stop-PSFFunction -Message "Failure on $computer" -ErrorRecord $_
            }
        }
    }
}