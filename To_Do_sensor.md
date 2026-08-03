# To_Do — Sensor EDR (pendientes de Fases 1 a 4)

Contexto: plan completo en la conversación de la rama `SensorEDR`. Las 4 fases
(correcciones, detecciones MITRE, inteligencia multi-fuente, vulnerabilidades
sobre inventario) están implementadas y verificadas por código/tests
automatizados. Fases 1 y 2 tienen partes **no verificadas en una máquina
Windows real** (el sensor no se puede probar fuera de Windows). Fases 3 y 4
corren enteramente en el servidor y sí se verificaron de punta a punta contra
una base de datos aislada — sus pendientes son de configuración/operación y
calidad del diccionario, no de lógica.

## Bloqueante — requiere Windows

- [ ] **Recompilar `sensor-setup.exe`** con `agent/build_exe.ps1` (PyInstaller +
      Inno Setup). El `.exe` actual en `public/sensor-setup.exe` es anterior a
      las Fases 1 y 2: no tiene la cola persistente, el supervisor de
      monitores, el watcher de credenciales multi-perfil, ni el motor de
      reglas MITRE (`rules.py`). El ZIP de descarga (`/api/sensors/download-package`)
      ya sirve la versión actualizada — solo el instalador `.exe` quedó atrás.
- [ ] **Verificar en vivo el Credential Store Watcher** (`agent/sensor.py`,
      `start_monitors()`, script `f_script`): el bloque `Register-ObjectEvent`
      con `-Action` corre en el runspace de eventos de PowerShell. Se corrigió
      el uso de `$using:` (inválido ahí) por `-MessageData` + `$Event.MessageData`,
      pero no se confirmó en una máquina real que el `Write-Output` de esa
      acción efectivamente llega al `stdout` del proceso PowerShell padre que
      lee `run_ps_monitor()`. Si no llega, la detección de infostealer
      (T1555.003, la más severa del sensor) sigue sin funcionar en la práctica
      pese al fix.
- [ ] **Probar el Registry Persistence Watcher** (T1547.001) end-to-end: crear
      una entrada en `HKLM:\...\Run` o `HKCU:\...\Run` en una máquina de
      prueba y confirmar que aparece en el timeline con `mitre_id=T1547.001`.
      La consulta WMI `RegistryValueChangeEvent` con `Hive`/`KeyPath` no se
      validó contra un registro real (solo revisada por lectura).
- [ ] **Probar el Service Creation Watcher** (T1543.003): crear un servicio de
      prueba (`sc create testsvc binPath= ...`) y confirmar que se detecta.
- [ ] **Confirmar el SHA256 diferido** (`_hash_if_suspicious`): que el archivo
      dispare el hash solo cuando corresponde (regla activada o ruta
      Temp/AppData/Downloads) y que el campo `file_hash` llegue al backend y
      se vea en `raw_json` de `sensor_telemetry`.
- [ ] Instalar el sensor actualizado como servicio (LocalSystem) en una
      máquina limpia y confirmar en el dashboard: watcher de credenciales
      activo, timeline con tipo real (no "INFO"), log rotativo escribiéndose
      en `sensor.log`, reinicio automático de un monitor si se mata su
      `powershell.exe` hijo.

## Pendiente de decisión / trabajo adicional (no bloqueante)

- [ ] **Extender el diccionario de reglas** de `agent/rules.py` con más LOLBins
      y técnicas si el pentesting real revela huecos — el set actual (~13
      reglas) cubre lo más común pero no es exhaustivo frente a MITRE
      Enterprise completo.
- [ ] **Evaluar cadenas padre-hijo más allá de Office→shell**: hoy
      `office_spawns_shell` es la única regla de linaje de proceso. Otras
      cadenas de interés (navegador→powershell, explorer→certutil con hijo
      inesperado) quedaron fuera del alcance de la Fase 2.
- [ ] **Firefox**: el Credential Store Watcher vigila
      `Profiles\*.default*\logins.json`, pero el patrón de nombre de carpeta de
      perfil de Firefox varía (`*.default-release`, perfiles múltiples); no se
      probó contra una instalación real de Firefox.
- [ ] **Botón "Software" del modal de endpoint**: sigue sin correlación de
      vulnerabilidades — eso es exactamente el alcance de la Fase 4
      (siguiente), no un pendiente de Fase 1/2.

## Riesgo conocido, aceptado por diseño (no acción, solo registro)

- El watcher de registro solo cubre 4 rutas fijas (`HKLM`/`HKCU` × `Run`/`RunOnce`).
  No cubre `RunServicesOnce`, `Winlogon\Shell`, tareas programadas por WMI, ni
  claves de extensión de shell — deliberadamente acotado al patrón más común
  de persistencia por registro para no disparar demasiados watchers WMI a la vez.
- `global.volatileTelemetry` (RAM del servidor) sigue perdiéndose entre
  invocaciones serverless. La Fase 3 lo mitiga parcialmente
  (`endpoint_network_observations` reconstruye qué contactó cada endpoint para
  la retro-correlación) pero no resuelve el timeline de "últimos 50 eventos"
  en sí, que sigue perdiendo datos entre invocaciones. Ver el plan completo.

## Pendientes de Fase 3 (motor de inteligencia multi-fuente)

- [ ] **Configurar `ABUSECH_AUTH_KEY`** en `.env` y en Vercel — sin ella,
      ThreatFox y MalwareBazaar (las dos mejores señales de C2/malware) quedan
      fuera de la ingesta diaria; solo Tor, Feodo, URLhaus y OTX aportan.
      Registro gratuito en `https://auth.abuse.ch/`.
- [ ] **Primera corrida real del cron `daily-jobs`** en Vercel (o disparo
      manual) para confirmar que el pipeline completo (feeds → OTX → ingesta
      de intel → retro-correlación → retención) termina dentro de los 60s de
      `maxDuration` y que `cron_runs`/`intel_source_state` reflejan el
      resultado. Solo se probó en local contra una base de datos aislada, con
      datos sintéticos — no contra el volumen real de ThreatFox/URLhaus.
- [ ] **Vigilar el consumo de escrituras de Turso** la primera semana tras
      activar la ingesta — el plan estimó ~880k escrituras/mes con las fuentes
      configuradas, dentro del límite gratuito de 10M, pero es una estimación
      sobre volúmenes de fuentes externas que cambian con el tiempo.
- [ ] **Feodo Tracker está prácticamente muerto** (verificado: 5 IPs, todas
      `offline`, sin actualizar desde marzo). Se ingiere igual porque cuesta
      poco, pero no debe presentarse en la UI como fuente confiable — si en
      algún momento se agrega una vista que liste fuentes activas, excluirla
      o marcarla como inactiva.
- [x] ~~URLhaus recent es mayoritariamente ruido para una flota Windows~~ —
      **resuelto**: `fetchUrlhausRecent` ahora **excluye por completo** (antes
      solo bajaba confianza a 15) las filas con tags `elf|mips|arm|mozi|mirai`,
      contándolas en `skippedIot` para observabilidad. El cursor de
      paginación sigue avanzando sobre todas las filas del CSV, incluidas las
      descartadas, para no reprocesarlas en la siguiente corrida. Verificado
      con un CSV sintético de 4 filas (2 IoT, 2 reales): las 2 IoT nunca
      llegan a `threat_indicators`.
- [x] ~~UI del motor de inteligencia~~ — **resuelto**: nueva vista "Threat
      Intel" en el sidebar (`ThreatIntelView`, `src/App.jsx`) con tarjetas de
      estado por fuente (marca Feodo como inactiva explícitamente), consulta
      manual (`POST /api/intel/lookup`) y tabla paginada de indicadores con
      filtros por tipo/fuente/búsqueda (`GET /api/intel/indicators`).
- [ ] **NVD_API_KEY** (opcional, mencionada en el plan para la Fase 4) —
      registrar en `https://nvd.nist.gov/developers/request-an-api-key` antes
      de la sincronización masiva inicial del catálogo CVE, o la primera carga
      de KEV+NVD será más lenta por el límite de 5 req/30s sin key.

## Pendientes de Fase 4 (vulnerabilidades sobre inventario)

- [ ] **Primera sincronización real del catálogo CVE** (KEV completo + rangos
      NVD para los ~24 productos del diccionario) en producción — sin
      `NVD_API_KEY`, la primera carga masiva puede necesitar varias corridas
      del cron para completarse (5 req/30s, paginado de 500 en 500). Solo se
      probó con datos sintéticos de un CVE inventado; nunca contra el volumen
      real de NVD.
- [ ] **Auditar cada hallazgo de la primera pasada real, uno por uno**, contra
      el aviso oficial del fabricante — es el paso de verificación que pide
      explícitamente el plan aprobado ("un solo falso positivo en la primera
      pasada invalida el diccionario para ese producto"). No se puede dar por
      buena la correlación solo porque el motor no truena.
- [ ] **Verificar en Windows real** que `agent/sensor.py` recolecta bien
      `HKEY_USERS\<SID>\...\Uninstall` para los perfiles con sesión activa, y
      que `Win32_QuickFixEngineering` + el UBR del registro llegan pobladas al
      backend (`sensor_endpoints.hotfixes` / `os_build`). Solo se probó con
      inventario sintético inyectado directo en la base de datos — el
      `report_sysinfo()` extendido en sí no corrió nunca contra un Windows
      real.
- [ ] **Ampliar el diccionario** más allá de los ~24 productos sembrados si el
      inventario real de los endpoints revela huecos grandes — el plan
      documenta que ~30-40% del inventario por número de filas queda sin
      mapear por diseño (redistribuibles VC++, drivers, bloatware de
      fabricante), pero conviene revisar qué aplicaciones *importantes*
      quedan en `unmapped_software` tras la primera semana real y decidir si
      ameritan una entrada nueva.
- [x] ~~`endpoint_vulnerabilities` sin política de retención~~ — **resuelto**:
      `cleanupRetention()` ahora purga hallazgos `status='resolved'` con más
      de 90 días desde `last_confirmed` (más generoso que telemetría porque
      siguen teniendo valor de auditoría). Los `open` nunca se tocan, sin
      importar su antigüedad. Verificado con 3 filas sintéticas (resuelta
      vieja, resuelta reciente, abierta vieja): solo se purga la primera.
- [x] ~~UI del catálogo/diccionario~~ — **resuelto**: nueva vista
      "Vulnerabilities" en el sidebar (`VulnerabilitiesView`, `src/App.jsx`)
      con el resumen global (`/api/vulns/summary`: totales por severidad, KEV,
      top CVEs) y una tabla del diccionario CPE con formulario para añadir
      entradas nuevas sin tocar código (`GET/POST /api/vulns/dictionary`).
      Verificado end-to-end: POST válido persiste y aparece en el GET
      siguiente, POST sin campos obligatorios devuelve 400, POST sin sesión
      devuelve 401.
