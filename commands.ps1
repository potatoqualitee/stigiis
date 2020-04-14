$commands = Get-Command *v-*

foreach ($command in $commands) {
    $name = $tags = $command.Name
    $code = $command.Definition
    $tags = $tags.Replace("V-","-").Split("-") -join ", V-"

    $name = "Get-Stg$name"
    Set-Content -Path "C:\github\stigiis\public\$name.ps1" -Value "function $name {"
    Add-Content -Path "C:\github\stigiis\public\$name.ps1" -Value "
    .NOTES
        Tags: $tags
        Author: Chrissy LeMaire (@cl), netnerds.net
        Copyright: (c) 2020 by Chrissy LeMaire, licensed under MIT
        License: MIT https://opensource.org/licenses/MIT"
    Add-Content -Path "C:\github\stigiis\public\$name.ps1" -Value $code
    Add-Content -Path "C:\github\stigiis\public\$name.ps1" -Value "}"
    Get-ChildItem -Path "C:\github\stigiis\public\$name.ps1"
}

