param(
    [string]$InstallDirectory = "",
    [string]$StartMenuDirectory = ""
)

$ErrorActionPreference = "Stop"

$source = Join-Path $PSScriptRoot "dist\Aegis.exe"
if (-not (Test-Path $source)) {
    throw "Aegis.exe was not found. Run build_windows.ps1 first."
}

if ([string]::IsNullOrWhiteSpace($InstallDirectory)) {
    $InstallDirectory = Join-Path $env:LOCALAPPDATA "Programs\K-tano-Aegis"
}
if ([string]::IsNullOrWhiteSpace($StartMenuDirectory)) {
    $StartMenuDirectory = [Environment]::GetFolderPath("Programs")
}

New-Item -ItemType Directory -Path $StartMenuDirectory -Force | Out-Null
$installDirectory = $InstallDirectory
New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
$installedExe = Join-Path $installDirectory "Aegis.exe"
Copy-Item -LiteralPath $source -Destination $installedExe -Force

$shortcutPath = Join-Path $StartMenuDirectory "Aegis.lnk"
$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
$shortcut.TargetPath = $installedExe
$shortcut.WorkingDirectory = $installDirectory
$shortcut.IconLocation = "$installedExe,0"
$shortcut.Save()

Write-Host "Aegis installed to $installDirectory"
Write-Host "Start menu shortcut created at $shortcutPath"


