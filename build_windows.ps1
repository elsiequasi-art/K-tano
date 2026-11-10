$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$venvPython = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    python -m venv (Join-Path $root ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the build environment."
    }
}

& $venvPython -m pip install -r (Join-Path $root "requirements-build.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the Windows packaging dependency."
}

$personaData = "$(Join-Path $root 'PERSONA.md');."
$sandboxRunnerData = "$(Join-Path $root 'aegis_sandbox_runner.py');."
$buildArgs = @(
    "-m",
    "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--name",
    "Aegis",
    "--add-data",
    $personaData,
    "--add-data",
    $sandboxRunnerData,
    "--distpath",
    (Join-Path $root "dist"),
    "--workpath",
    (Join-Path $root "build"),
    "--specpath",
    (Join-Path $root "build"),
    (Join-Path $root "aegis_app.py")
)
& $venvPython @buildArgs
if ($LASTEXITCODE -ne 0) {
    throw "Windows packaging failed."
}

Write-Host "Built $(Join-Path $root 'dist\Aegis.exe')"


