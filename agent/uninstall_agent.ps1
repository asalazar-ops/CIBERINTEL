<#
.SYNOPSIS
    Script para detener el proceso del Sensor de CyberIntel EC y eliminar sus archivos.
#>

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Desinstalador del Agente CyberIntel EC" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Detener el proceso de Python que está corriendo el sensor
Write-Host "[*] Buscando procesos del agente..." -ForegroundColor Yellow
$procesos = Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -match "sensor.py" }

if ($procesos) {
    foreach ($p in $procesos) {
        Write-Host "    Deteniendo proceso PID: $($p.ProcessId)" -ForegroundColor Red
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] Procesos detenidos correctamente." -ForegroundColor Green
} else {
    Write-Host "[-] No se encontró ningún agente en ejecución." -ForegroundColor DarkGray
}

# 2. Eliminar el archivo del sensor (opcional, por defecto asume que está en la misma carpeta o ruta conocida)
$sensorPath = Join-Path -Path $PWD -ChildPath "agent\sensor.py"
if (Test-Path $sensorPath) {
    Remove-Item -Path $sensorPath -Force
    Write-Host "[+] Archivo sensor.py eliminado de $sensorPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "Desinstalación completada." -ForegroundColor Cyan
Pause
