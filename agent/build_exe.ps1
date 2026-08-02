<#
.SYNOPSIS
    Compila sensor.py a un .exe standalone (PyInstaller) y luego el instalador
    con Inno Setup. Requiere Python con pyinstaller/pywin32 instalados y
    Compil32/ISCC de Inno Setup 6 en el PATH (o ajustar $IsccPath abajo).

.EXAMPLE
    cd agent
    .\build_exe.ps1
#>

$ErrorActionPreference = "Stop"
$AgentDir = $PSScriptRoot

Write-Host "[1/3] Compilando sensor.exe con PyInstaller..." -ForegroundColor Cyan
Push-Location $AgentDir
try {
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    if (Test-Path "sensor.spec") { Remove-Item -Force "sensor.spec" }

    python -m PyInstaller --onefile --name sensor --hidden-import win32timezone --console sensor.py
    if (-not (Test-Path "dist\sensor.exe")) {
        throw "PyInstaller no generó dist\sensor.exe"
    }
} finally {
    Pop-Location
}
Write-Host "[+] sensor.exe generado en agent\dist\sensor.exe" -ForegroundColor Green

Write-Host "[2/3] Compilando el instalador con Inno Setup..." -ForegroundColor Cyan
$IsccCandidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    (Get-Command iscc -ErrorAction SilentlyContinue).Source
) | Where-Object { $_ -and (Test-Path $_) }

if (-not $IsccCandidates) {
    throw "No se encontró ISCC.exe de Inno Setup 6. Instálalo con: winget install JRSoftware.InnoSetup"
}
$Iscc = $IsccCandidates[0]

& $Iscc "$AgentDir\installer\sensor.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC.exe falló con código $LASTEXITCODE" }

Write-Host "[3/3] Instalador generado en agent\installer\output\CyberIntelSensorSetup.exe" -ForegroundColor Green
