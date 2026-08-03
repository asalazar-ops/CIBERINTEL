# To_Do — Sensor EDR (pendientes de Fases 1 a 4)

Contexto: plan completo en la conversación de la rama `SensorEDR`. Las 4 fases
(correcciones, detecciones MITRE, inteligencia multi-fuente, vulnerabilidades
sobre inventario) están implementadas y verificadas por código/tests
automatizados. Todo lo que quedaba resoluble por código ya se resolvió (ver
commits `d73a25e` y `df20b3c`). Lo que sigue son **acciones que solo el
usuario puede ejecutar**: requieren una máquina Windows real, claves de API
externas, o desplegar y observar producción — nada de esto es código pendiente.

Organizado en 4 fases de ejecución, en el orden recomendado: cada fase
desbloquea la siguiente.

---

## Fase A — Recompilar y reinstalar el sensor en Windows

Objetivo: que el `.exe` que descarga el dashboard sea el mismo código que ya
está en el repo, y confirmar en una máquina real que todo lo nuevo funciona.

### A.1 — Recompilar `sensor-setup.exe`
- [ ] En la máquina Windows con Python + PyInstaller + Inno Setup: `cd agent && .\build_exe.ps1`
- [ ] Verificar que genera `agent/dist/sensor.exe` y luego `agent/installer/output/CyberIntelSensorSetup.exe`
- [ ] Copiar ese instalador a `public/sensor-setup.exe` (reemplazando el actual)
- [ ] Commit + push de `public/sensor-setup.exe` (es un binario — confirmar que no se comitea nada más por accidente)

### A.2 — Reinstalar y verificar en vivo
Desinstalar la versión vieja del servicio primero (si sigue instalada), luego instalar la nueva y comprobar, en orden:

- [ ] Servicio instalado como `Running` / `Automatic` (igual que en la instalación anterior de referencia)
- [ ] **Credential Store Watcher**: tocar `Login Data` de Chrome (o iniciar sesión en un sitio) y confirmar que aparece una detección T1555.003 en el dashboard — esta es la prueba más importante porque el fix de `-MessageData` nunca se confirmó en vivo
- [ ] **Registry Persistence Watcher**: crear una entrada en `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run` (o `HKCU` equivalente) y confirmar `mitre_id=T1547.001` en el timeline
- [ ] **Service Creation Watcher**: `sc create testsvc binPath= "C:\Windows\System32\notepad.exe"` y confirmar `mitre_id=T1543.003`, luego `sc delete testsvc` para limpiar
- [ ] **Hash diferido**: ejecutar algo desde `%TEMP%` o `Downloads` y confirmar que `file_hash` llega poblado en `raw_json` de `sensor_telemetry`
- [ ] **Log rotativo**: confirmar que `sensor.log` se escribe junto al ejecutable
- [ ] **Supervisor de monitores**: matar un proceso `powershell.exe` hijo del sensor (Task Manager) y confirmar que se reinicia solo, con el mensaje correspondiente en el log
- [ ] **Inventario extendido**: confirmar en la pestaña Software del endpoint que aparecen apps instaladas por usuario (`HKCU`), y en el modal de Vulnerabilidades que `os_build`/hotfixes llegaron (se puede verificar indirectamente: si el catálogo CVE ya está sincronizado — Fase C — debería poder correlacionar software real de esa máquina)

**Nota:** las últimas dos verificaciones de A.2 dependen de que la Fase C ya haya corrido al menos una vez (necesitas CVEs en el catálogo para que la correlación produzca algo que mirar). Si llegas a A.2 antes que a C, puedes confirmar el inventario crudo revisando `sensor_endpoints.software_info`/`hotfixes` directo en la base, y volver a la vista de Vulnerabilidades después.

---

## Fase B — Activar las fuentes de inteligencia que faltan

Objetivo: que ThreatFox y MalwareBazaar (las señales de mayor calidad del motor de intel) dejen de estar deshabilitadas.

- [ ] Registrarte en `https://auth.abuse.ch/` y generar una Auth-Key gratuita
- [ ] Añadir `ABUSECH_AUTH_KEY=<key>` a `.env` local
- [ ] Añadir la misma variable en Vercel (Project Settings → Environment Variables) para producción
- [ ] Opcional pero recomendado antes de la Fase C: registrar `NVD_API_KEY` en `https://nvd.nist.gov/developers/request-an-api-key` (sin ella, la sincronización de CVEs de la Fase C es ~10x más lenta por el límite de tasa)

---

## Fase C — Primera corrida real de los crons en producción

Objetivo: confirmar que el pipeline diario completo funciona con datos reales, no solo con los sintéticos que usamos en las pruebas locales.

- [ ] Desplegar a Vercel con las variables de la Fase B ya configuradas
- [ ] Disparar `daily-jobs` manualmente la primera vez (no esperar a las 03:00 UTC) para no perder un día de diagnóstico — revisar en el panel de Vercel que termina dentro de los 60s
- [ ] Revisar en el dashboard (vista Threat Intel) que `intel_source_state` muestra `last_status: ok` para torexit, threatfox, urlhaus, malwarebazaar, otx (feodo puede seguir en estado degradado, es esperado)
- [ ] Disparar `scan-assets` manualmente la primera vez — esta corrida sincroniza KEV + NVD + EPSS y corre la primera correlación de vulnerabilidades
- [ ] Revisar en la vista Vulnerabilities que `catalog.cves` y `catalog.ranges` ya no están en 0
- [ ] Si no tienes `NVD_API_KEY`: puede que la primera sincronización de NVD no complete en una sola corrida (límite 5 req/30s) — repetir la corrida manual del cron un par de veces más, o simplemente dejar que las corridas diarias automáticas la completen en unos días
- [ ] A partir de aquí, dejar que ambos crons corran solos (03:00 y 04:00 UTC) y volver en una semana para la Fase D

---

## Fase D — Validación de calidad y ajuste fino

Objetivo: confirmar que lo que el motor está reportando es correcto y útil, no ruido.

- [ ] **Auditar manualmente cada hallazgo de vulnerabilidades de la primera semana**, uno por uno, contra el aviso oficial del fabricante (NVD/CVE.org o el sitio del vendor) — un solo falso positivo invalida esa entrada del diccionario para ese producto y hay que corregirla o quitarla desde la vista Vulnerabilities
- [ ] Revisar `unmapped_software` (visible como aviso en la pestaña Vulnerabilidades de cada endpoint) y decidir si algún producto importante amerita añadirse al diccionario — usar el formulario de la vista Vulnerabilities, sin tocar código
- [ ] Vigilar el consumo de escrituras de Turso en su panel — el estimado del plan fue ~880k/mes, dentro del límite gratuito de 10M, pero es una estimación
- [ ] Revisar el volumen real ingerido de URLhaus tras el filtro IoT (ya no debería ser miles de filas irrelevantes) y confirmar que lo que queda es señal razonable
- [ ] Con datos reales de varias semanas, decidir si conviene: extender `agent/rules.py` con más técnicas LOLBins/cadenas padre-hijo, o extender el Credential Store Watcher a más variantes de perfil de Firefox — ambos quedaron señalados como "no bloqueante" en el diseño original porque sin telemetría real no había forma de priorizar qué agregar primero

---

## Riesgo conocido, aceptado por diseño (no acción, solo registro)

- El watcher de registro solo cubre 4 rutas fijas (`HKLM`/`HKCU` × `Run`/`RunOnce`).
  No cubre `RunServicesOnce`, `Winlogon\Shell`, tareas programadas por WMI, ni
  claves de extensión de shell — deliberadamente acotado al patrón más común
  de persistencia por registro para no disparar demasiados watchers WMI a la vez.
- `global.volatileTelemetry` (RAM del servidor) sigue perdiéndose entre
  invocaciones serverless. La Fase 3 lo mitiga parcialmente
  (`endpoint_network_observations` reconstruye qué contactó cada endpoint para
  la retro-correlación) pero no resuelve el timeline de "últimos 50 eventos"
  en sí, que sigue perdiendo datos entre invocaciones.
- Feodo Tracker está prácticamente muerto (5 IPs, todas `offline`, sin
  actualizar desde marzo). Se ingiere igual porque cuesta poco, y la UI ya lo
  marca como fuente inactiva — no requiere acción, es informativo.
