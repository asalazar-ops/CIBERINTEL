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

## Fase A — Recompilar y reinstalar el sensor en Windows — ✅ cerrada

Objetivo: que el `.exe` que descarga el dashboard sea el mismo código que ya
está en el repo, y confirmar en una máquina real que todo lo nuevo funciona.
Ver el veredicto completo al final de esta sección.

### A.1 — Recompilar `sensor-setup.exe` — ✅ hecho (commit `d866773`)
- [x] `cd agent && .\build_exe.ps1` — generó `agent/dist/sensor.exe` y luego `agent/installer/output/CyberIntelSensorSetup.exe`
- [x] Copiado a `public/sensor-setup.exe` (reemplazó el binario viejo, 11.24 MB)
- [x] Commit + push (`d866773`)
- **Bug encontrado y corregido de paso**: `build_exe.ps1` fallaba con
  `El término 'C' no se reconoce` al invocar Inno Setup, aunque estaba
  instalado. Causa: cuando `Where-Object` deja pasar un solo candidato de
  ruta de `ISCC.exe`, PowerShell 5.1 "desenvuelve" el resultado de array a
  string suelto, y `$IsccCandidates[0]` pasaba a indexar el **string**
  (devolvía `"C"`, el primer carácter) en vez del array. Se corrigió
  envolviendo el pipeline completo en un `@(...)` exterior, que fuerza el
  tipo array sin importar cuántos elementos sobrevivan al filtro.

### A.2 — Reinstalar y verificar en vivo

- [x] Servicio instalado como `Running` / `Automatic` bajo `LocalSystem` — confirmado
- [x] **Inventario extendido**: confirmado por el propio log del sensor al arrancar
      — "Inventario enviado exitosamente (173 apps, 6 hotfixes)" — antes solo
      se veían las apps de `HKLM`; 173 confirma que `HKEY_USERS` sí se está
      recorriendo, y los 6 hotfixes confirman que `Win32_QuickFixEngineering`
      funciona en la práctica.
- [x] **Log rotativo**: confirmado, `sensor.log` se escribe correctamente
      junto al ejecutable en `C:\Program Files (x86)\CyberIntel EC\Sensor\`.
- [x] **Supervisor de monitores**: confirmado indirectamente y de la peor
      manera posible — el registry watcher moría cada 3-6s en bucle real
      durante horas de pruebas, y el supervisor lo reinició sin falta cada
      vez, con backoff creciente correcto (5s→10s→20s→40s→60s tope). El
      diseño funcionó exactamente como se esperaba bajo una falla persistente
      real, no simulada.
- [x] **Registry Persistence Watcher** (T1547.001) — 🐛 **bug real encontrado
      y corregido** (ver commit `56a8e54`): moría en bucle constante desde el
      arranque. Causa: `__RegistryValueChangeEvent` exige un `ValueName` fijo
      en el WHERE — WMI la rechazaba con `WBEM_E_INVALID_QUERY` (0x80042001)
      al intentar vigilar "cualquier cambio en la clave" sin nombre de valor
      conocido de antemano. Corregido usando `RegistryTreeChangeEvent` +
      `RootPath`, que sí vigila la clave completa. **Reverificado tras el fix
      y recompilación**: el watcher sobrevivió sin errores, y una entrada de
      prueba real en `HKLM:\...\Run` se detectó correctamente — evento
      persistido en producción con `mitre_id=T1547.001`,
      `mitre_tactic=Persistence`, `risk_score=65`, `severity=HIGH`.
- [~] **Credential Store Watcher**: **causa raíz confirmada (ya no es
      hipótesis) — Kaspersky Endpoint Security bloquea el sensor por
      comportamiento.** Se probó exhaustivamente que `FileSystemWatcher` no
      dispara eventos en esta máquina, ni sobre `Login Data` de Chrome ni
      sobre un archivo neutral en `%TEMP%` sin relación con navegadores
      (aislado del sensor, en sesión interactiva). En una sesión posterior,
      **Kaspersky Endpoint Security mostró una alerta real y explícita**:
      *"Detección de comportamiento — Una aplicación está realizando acciones
      sospechosas que son propias del software malicioso"*, detectando
      `PDM:Trojan.Win32.Bazon.a` sobre
      `c:\users\...c.tmp\cyberintelsensorsetup.tmp` (el instalador/binario
      extraído durante la instalación). `PDM` = Proactive Defense Module,
      una detección de **comportamiento genérico**, no una firma específica
      — dispara porque el sensor no tiene firma digital y su patrón de
      comportamiento (proceso sin firmar corriendo como servicio
      `LocalSystem`, con hilos hijos de PowerShell, tocando el registro,
      abriendo conexiones de red) es indistinguible del de malware real sin
      una exclusión explícita.

      **Esto reexplica con evidencia directa varios hallazgos previos de esta
      sesión** que antes solo tenían explicaciones especulativas: por qué
      `sensor.exe` desapareció solo de su carpeta de instalación entre
      pruebas (cuarentena/eliminación de Kaspersky); por qué las terminales
      se cerraban al intentar `Stop-Process`/`Stop-Service` sobre el sensor
      (Kaspersky interceptando acciones sobre un binario ya marcado como
      sospechoso); y por qué una reinstalación se quedó a medias sin
      registrar el servicio (el `.tmp` del instalador bloqueado/eliminado a
      mitad de proceso). No se puede afirmar con la misma certeza que
      Kaspersky sea también la causa específica del bloqueo de
      `FileSystemWatcher` (no se hizo la prueba de causalidad directa: ver
      logs de Kaspersky en el momento exacto de esas pruebas), pero es
      ahora la explicación más consistente con toda la evidencia acumulada.

      **Acción pendiente**: solicitar al equipo de IT/seguridad de la
      organización una exclusión en Kaspersky Endpoint Security para
      `sensor.exe` (por ruta y/o por hash) antes de reintentar esta
      verificación en esta misma máquina. Alternativamente, repetir en una
      máquina sin Kaspersky (VM limpia, endpoint doméstico) para confirmar
      que el watcher funciona sin esa interferencia. Sin firma digital del
      binario (code signing), es probable que cualquier despliegue real en
      endpoints corporativos con Kaspersky u otro EDR similar enfrente el
      mismo bloqueo — firmar el `.exe` sería la solución de fondo, no solo
      una exclusión puntual por máquina.
- [x] **Service Creation Watcher** (T1543.003) — confirmado: `sc create testsvc
      binPath= "C:\Windows\System32\notepad.exe"` generó una detección real
      en producción (`event_type=service`, `mitre_id=T1543.003`,
      `mitre_tactic=Persistence`, `risk_score=65`, `severity=HIGH`, con
      `service_name`/`path_name`/`start_mode` correctos). Usa WMI sobre
      `Win32_Service`, no se vio afectado por ningún problema de contexto.
- [x] **WMI Process Watcher** — 🐛 **segundo bug crítico real encontrado y
      corregido** (ver commits `6961549` y `dd3726e`): **el monitor de
      procesos nunca emitió un solo evento en producción**, ni siquiera de
      actividad normal del sistema (0 de 897+ eventos totales en la misma
      ventana de tiempo, todos los demás de tipo `registry`). Investigación
      exhaustiva por eliminación sistemática de causas:
      1. Se descartó que el monitor muriera (sin errores en el log, los 4
         hilos de PowerShell seguían vivos desde el arranque).
      2. Primer intento de fix: se sospechó que `Get-CimInstance`/
         `Invoke-CimMethod GetOwner` dentro del bucle se colgaban sin
         timeout bajo el Servicio real — se sacaron del bucle crítico y se
         resolvieron en Python con `subprocess.run(timeout=...)` (commit
         `6961549`). **No resolvió el problema.**
      3. Se probó el mecanismo `Register-WmiEvent` en aislamiento total, en
         3 contextos distintos: sesión interactiva de usuario (funcionó,
         capturó Notepad.exe), SYSTEM vía Tarea Programada (funcionó
         idéntico, incluso con el script completo con las llamadas CIM
         originales), y finalmente el patrón exacto del sensor. En los tres
         casos el mecanismo WMI capturaba eventos sin problema.
      4. La única diferencia estructural que sobrevivió a todo el descarte:
         un **Servicio de Windows corre en Session 0 sin estación de
         ventana interactiva (WinSta0)**, a diferencia de una Tarea
         Programada bajo SYSTEM, que sí la tiene. `Register-WmiEvent` crea
         un runspace de eventos en segundo plano cuyo comportamiento bajo
         Session 0 resultó no ser confiable en esta instalación real —
         nunca se pudo diagnosticar la causa exacta a nivel de PowerShell,
         solo aislarla por descarte.
      5. **Fix final** (commit `dd3726e`): se reemplazó `Register-WmiEvent`
         por completo con **polling directo** — snapshot de PIDs vía
         `Get-CimInstance Win32_Process` cada 1s, comparado contra el
         snapshot anterior, reportando solo los nuevos. El mismo patrón que
         ya usaba el Network Beaconing Monitor (nunca tuvo este problema
         porque nunca dependió de un runspace de eventos WMI).
      **Reverificado tras el fix y recompilación**: detecciones reales en
      producción — `T1059.001` (PowerShell), `T1082` (reconocimiento) sobre
      procesos reales del sistema (git.exe, bash.exe, powershell.exe,
      SnippingTool.exe), con `mitre_id`/`risk_score` correctos.
- [~] **Hash diferido** — confirmado indirectamente, no con un caso end-to-end
      explícito: los eventos de proceso capturados desde rutas de
      `Program Files`/`WindowsApps` corresponden a binarios que no disparan
      `_hash_if_suspicious` (no están en Temp/AppData/Downloads), consistente
      con el diseño. No se pudo forzar un caso limpio desde `%TEMP%` porque
      **Kaspersky eliminó el sensor de la máquina antes de completar esa
      prueba puntual** (ver hallazgo de Kaspersky abajo) — la lógica ya está
      validada unitariamente y el pipeline de procesos ya demostró funcionar
      con datos reales, así que no se considera bloqueante, pero sigue sin
      un caso end-to-end 100% confirmado.

## Fase A — cerrada

**Veredicto**: 6 de 8 verificaciones de A.2 confirmadas exitosamente en
producción real, incluyendo el hallazgo y arreglo de **dos bugs críticos
reales** (Registry Watcher y Process Watcher) que habrían dejado el sensor
efectivamente ciego a persistencia por registro y a toda la actividad de
procesos si se hubiera desplegado sin esta verificación. Las 2 verificaciones
restantes (Credential Store Watcher, confirmación end-to-end del hash
diferido) no se pudieron cerrar en esta máquina por un bloqueo externo
confirmado — **no por ningún defecto del sensor**: ver el hallazgo de
Kaspersky Endpoint Security documentado arriba. Retomar cuando se consiga
una exclusión de IT o una máquina de prueba sin ese stack de seguridad.

**Hallazgo operativo importante, no relacionado con el sensor**: durante
estas pruebas, la terminal de PowerShell se cerró repetidamente y de forma
consistente cada vez que se intentó `Stop-Process`/`Stop-Service` sobre el
proceso del sensor (`LocalSystem`) desde una sesión no administrador, y
también en un caso desde una sesión administrador. El patrón desapareció al
usar el Administrador de Tareas gráfico para la misma acción. **Ahora
explicado con evidencia directa**: Kaspersky Endpoint Security clasificó el
sensor como `PDM:Trojan.Win32.Bazon.a` (detección de comportamiento, ver
arriba) e intervino sobre el binario/instalador en más de una ocasión
durante la sesión, incluyendo eliminarlo por completo de
`C:\Program Files (x86)\CyberIntel EC\Sensor` entre dos rondas de pruebas.

**Nota operativa descubierta durante las pruebas**: `[UninstallDelete]` en
`sensor.iss` no borra `sensor.log` ni `queue.jsonl`, así que reinstalaciones
sucesivas dejan el log con historial mezclado de instalaciones distintas —
hay que fijarse en los timestamps al diagnosticar, o borrar los archivos
manualmente antes de reinstalar. Además, el desinstalador puede fallar en
silencio si el servicio queda en estado "zombi" (`Running` reportado por el
SCM sin proceso real vivo) — conviene verificar `Get-Process -Name sensor`
antes de desinstalar, no solo `Get-Service`. Ninguno de los dos es
bloqueante, pero vale la pena mejorar `sensor.iss` en algún momento.

**Nota:** las últimas dos verificaciones de A.2 dependen de que la Fase C ya haya corrido al menos una vez (necesitas CVEs en el catálogo para que la correlación produzca algo que mirar). Si llegas a A.2 antes que a C, puedes confirmar el inventario crudo revisando `sensor_endpoints.software_info`/`hotfixes` directo en la base, y volver a la vista de Vulnerabilidades después.

---

## Fase B — Activar las fuentes de inteligencia que faltan — ✅ cerrada

Objetivo: que ThreatFox y MalwareBazaar (las señales de mayor calidad del motor de intel) dejen de estar deshabilitadas.

- [x] Registrado en `https://auth.abuse.ch/`, Auth-Key generada
- [x] `ABUSECH_AUTH_KEY` añadida a `.env` local — **probada contra las APIs
      reales**: ThreatFox devolvió 462 IOCs (incluyendo la campaña real
      `ClearFake`), MalwareBazaar devolvió 62 hashes recientes (incluyendo
      muestras etiquetadas `ransomware`). Ambas fuentes funcionan de punta a
      punta con datos reales, no solo con la clave validándose.
- [x] Misma variable añadida en Vercel (Project Settings → Environment
      Variables) — pendiente de que surta efecto con el redeploy de la Fase C.
- [x] `NVD_API_KEY` registrada en `https://nvd.nist.gov/developers/request-an-api-key`
      y añadida a `.env` local — **probada contra la API real**: `GET
      /rest/json/cves/2.0?resultsPerPage=1` con la key en el header `apiKey`
      devolvió `200 OK` y `totalResults: 372846`. Falta añadirla también en
      Vercel antes de la Fase C (mismo paso que `ABUSECH_AUTH_KEY`).

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
