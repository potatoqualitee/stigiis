$script:ModuleRoot = $PSScriptRoot

if ($env:appveyor) {
    $env:psmodulepath = "$env:psmodulepath; C:\projects; C:\projects\stigiis"
}

$PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'