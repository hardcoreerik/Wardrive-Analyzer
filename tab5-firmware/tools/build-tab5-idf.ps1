param(
  [switch]$Flash,
  [string]$Port = 'COM17'
)

# This project's build/ directory is configured against the PlatformIO-
# bundled ESP-IDF + Python venv (.pio-venv), NOT the separate standalone
# Espressif installation at C:\Espressif (that's what OrcSDR's sibling
# script, apps/orcsdr-tab5/tools/build-tab5-idf.ps1, uses -- confirmed by
# testing it directly here: CMake refuses to mix toolchains once a build
# dir is configured, error "python.exe ... is currently active ... while
# the project was configured with ... .pio-venv ... Run idf.py fullclean").
# This is the PlatformIO-toolchain equivalent of that script.
#
# Avoids the fragile part of doing this by hand: `idf_tools.py export
# --format key-value` emits a PATH value ending in a literal "%PATH%"
# placeholder meant for cmd.exe. PowerShell's Set-Item won't expand
# that, so a naive apply silently drops the rest of the system PATH --
# including `git` -- unless you substitute it back in yourself, as below.

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$origPath = $env:PATH
$env:IDF_PATH = 'C:\Users\hardc\.platformio\packages\framework-espidf'
$py = 'F:\Ai\WardriveAPP\Wardrive-Analyzer-M5Tab5\.pio-venv\Scripts\python.exe'
$exports = & $py "$env:IDF_PATH\tools\idf_tools.py" export --format key-value 2>$null
foreach ($line in $exports) {
  if ($line -match '^([^=]+)=(.*)$') {
    $val = $matches[2] -replace '%PATH%', $origPath
    Set-Item -Path ("Env:" + $matches[1]) -Value $val
  }
}

& $py "$env:IDF_PATH\tools\idf.py" build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Flash) {
  & $py "$env:IDF_PATH\tools\idf.py" -p $Port flash
  exit $LASTEXITCODE
}
