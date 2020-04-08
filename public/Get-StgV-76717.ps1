function Get-StgV-76717 {
<#
    .SYNOPSIS
        Remove all *.jpp,*.java files for vulnerability 76717.

    .DESCRIPTION
        Remove all *.jpp,*.java files for vulnerability 76717.

    .NOTES
        Tags: V-76717
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT

#>

    Write-PSFMessage -Level Verbose -Message "Configuring STIG Settings for $($MyInvocation.MyCommand)"

    $JavaFiles = Get-ChildItem -Path $env:SystemDrive -File -Include *.jpp,*.java -Recurse -Force -ErrorAction SilentlyContinue

    if($JavaFiles) {

        $JavaFiles | Remove-Item -Force
        $PostFiles = Get-ChildItem -Path $env:SystemDrive -File -Include *.jpp,*.java -Recurse -Force -ErrorAction SilentlyContinue

        [pscustomobject] @{

            Vulnerability = 'V-76717'
            Computername = $env:COMPUTERNAME
            FilesRemoved = $JavaFiles
            Compliant = if(!($PostFiles)) {

                "Yes: Files found and removed"
            }

            else {

                "No: File removal incomplete"
            }
        }
    }

    else {

        [pscustomobject] @{

            Vulnerability = 'V-76717'
            Computername = $env:COMPUTERNAME
            FilesToRemove = "No files found"
            Compliant = "Yes"
        }
    }

}
