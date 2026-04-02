param(
  [ValidateSet("x64", "Win32")]
  [string]$Arch = "x64",
  [ValidateSet("Debug", "Release")]
  [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $root "build\plugin\$Arch"

cmake -S (Join-Path $root "plugin") -B $buildDir -A $Arch
cmake --build $buildDir --config $Config

Write-Host "Built plugin into $buildDir\dist"
