function Get-StgMimeMapping {
<#
    .SYNOPSIS
        Remove required MIME mappings for vulnerability 76711 & 76797.

    .DESCRIPTION
        Remove required MIME mappings for vulnerability 76711 & 76797.

    .PARAMETER ComputerName
        The target server.

    .PARAMETER Credential
        Login to the target computer using alternative credentials.

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-76711, V-76797
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
        #Pre-Configuration MIME map collection
        $PreMimeConfig = (Get-WebConfiguration //staticcontent).Collection

        #Adjusted MIM map collection
        $NewCollection = ($PreMimeConfig | where {$_.fileextension -ne '.exe' -and $_.fileextension -ne '.dll' -and $_.fileextension -ne '.com' -and $_.fileextension -ne '.bat' -and $_.fileextension -ne '.csh'})

        #Set new configurations
        Set-WebConfigurationProperty //staticContent -Name Collection -InputObject $NewCollection

        $PostMimeConfig = (Get-WebConfiguration //staticcontent).Collection

        [pscustomobject] @{
            Vulnerability = 'V-76711, V-76797'
            Computername = $env:COMPUTERNAME
            PreConfigExtenstions = $PreMimeConfig.FileExtension
            PreConfigCount = $PreMimeConfig.Count
            PostConfigurationExtenstions = $PostMimeConfig.FileExtension
            PostConfigurationCount = $PostMimeConfig.Count
        }
    }
}