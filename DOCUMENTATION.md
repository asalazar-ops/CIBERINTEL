# 🛡️ CyberIntel EC — EDR & Behavioral Analytics

Documentación técnica completa del sistema de detección y respuesta en endpoints (EDR) con análisis de comportamiento en tiempo real, y de cómo está desplegado sobre Vercel.

---

## 🏗️ Arquitectura del Sistema

El sistema se basa en un modelo de tres capas más un cuarto componente de infraestructura para el trabajo asíncrono:

1.  **Sensor Agente (Python 3.x)**: Script nativo que corre en los endpoints Windows. No requiere instalación de dependencias externas (`pip`).
2.  **Backend (Node.js/Express en Vercel Serverless)**: `server/app.js` contiene toda la app; `api/index.js` la expone como función serverless. Gestiona la base de datos Turso (libSQL), procesa telemetría y valida amenazas contra OTX (AlienVault).
3.  **Analyst Dashboard (React/Vite)**: Interfaz web servida como estático por Vercel, que visualiza eventos en tiempo real y permite la gestión de dispositivos.
4.  **Vercel Cron (`api/cron/`)**: refresco de feeds/OTX, limpieza de telemetría y escaneo de assets — trabajo que antes vivía en `setInterval` dentro del proceso Node, inviable en serverless porque no hay proceso persistente entre invocaciones.

---

## 📡 Sensor Agente: Funcionamiento Interno

El agente es multihilo y asíncrono, diseñado para no bloquear el sistema operativo del usuario.

### 🆔 Identidad y Persistencia
-   **Hardware-ID**: Utiliza el **Número de Serie del BIOS** como identificador primario (`agent_id`). Esto evita duplicados en la consola si el agente se reinstala o actualiza.
-   **Registro (Heartbeat)**: Al iniciar, el agente DEBE registrarse en el endpoint `/heartbeat`. Hasta que el servidor no confirme la conexión, el agente no inicia los monitores.

### 🔒 Canal de comunicación
-   **`server_url`** apunta al dominio HTTPS de Vercel (`https://tu-app.vercel.app`), no a un puerto local.
-   **TLS**: por defecto (`ca_cert: null`) el agente confía en la CA pública del sistema, ya que
    Vercel sirve un certificado válido de una autoridad reconocida. Solo se pinnea un `ca_cert`
    local cuando el servidor de destino es el modo local (`node server.js` con certificado
    autofirmado). Si el handshake falla por un bug conocido de OpenSSL 3.0.x en Windows ("EE
    certificate key too weak" contra claves RSA perfectamente válidas), el agente reintenta una
    vez con `SECLEVEL=0`, sin dejar de verificar la cadena de confianza.
-   **`poll_interval_seconds`** (config, default 30s): cada consulta a `/check` es una invocación
    de función serverless facturable — a 5s serían ~17.000 invocaciones/día por agente.

### 🕵️ Motores de Monitoreo (Real-Time)
1.  **WMI Process Watcher**: Utiliza eventos de instrumentación de Windows para detectar la creación de procesos al instante.
    -   *Heurística*: Detecta ejecuciones desde carpetas críticas como `\Temp\`.
2.  **FileSystem Watcher**: Monitorea accesos a archivos sensibles.
    -   *Protección Específica*: Detecta intentos de lectura en las bases de datos de Google Chrome (prevención de Infostealers).
3.  **Network Beaconing Monitor**:
    -   **Frecuencia**: Escaneo cada 30 segundos de conexiones TCP establecidas.
    -   **Optimización**: Implementa un **Caché Local de 6 Horas**. Si una conexión a una IP/Puerto ya fue reportada, el agente guarda silencio durante 6 horas para ahorrar ancho de banda y API calls, a menos que sea una conexión nueva.

### 📤 Pipeline de Telemetría
-   Utiliza una **cola thread-safe** (`queue.Queue`).
-   Los eventos se agrupan y se envían por lotes (batches) al canal de `/telemetry`.

---

## 🖥️ Servidor: Procesamiento y Seguridad

### 🔒 Capa de Seguridad

-   **Autenticación de dashboard**: login único (`server/auth.js`) sin tabla de usuarios, sesión
    en cookie HttpOnly/Secure vía JWT. Sin `AUTH_SECRET` configurado, nadie puede iniciar sesión.
-   **Autenticación de sensores**: toda petición del agente lleva `AGENT_TOKEN`, comparado en
    **tiempo constante** (`requireAgentToken`). Si `AGENT_TOKEN` no está definido, el canal
    **falla cerrado** (rechaza todo) en lugar de aceptar un valor por defecto conocido.
-   **Autenticación de crons**: `/api/cron/*` exige `Authorization: Bearer $CRON_SECRET`; Vercel
    lo añade automáticamente cuando la variable está configurada.
-   **Webhook de Apify**: `/api/webhooks/apify/brand-monitor` exige `APIFY_WEBHOOK_SECRET` por
    cabecera — sin él, el webhook queda cerrado.
-   **Aislamiento**: en Vercel no existen puertos separados (todo entra por :443); el aislamiento
    entre rutas de gestión y canal de sensores lo dan `requireAuth`/`requireAgentToken`, no un
    puerto. El modo local (`node server.js`) sigue abriendo `:3001` (dashboard, solo loopback) y
    `:8443` (sensores) como capa adicional válida solo en ese entorno.

### 🧠 Inteligencia de Amenazas
-   **Integración OTX**: el servidor intercepta cada IP externa reportada y consulta la base de datos de AlienVault OTX para identificar IPs maliciosas de C2 (Command & Control). El caché de pulses/indicadores vive en la tabla `otx_cache` de Turso (antes era un objeto en memoria, incompatible con serverless) y se refresca vía el cron `daily-jobs`.
-   **Puntuación de Riesgo (Risk Score)** — por evento:
    -   `0`: Informativo.
    -   `1-59`: Sospechoso (almacenado en DB).
    -   `60+`: Crítico (alerta inmediata).

### 📉 Score de Comportamiento del Endpoint
Distinto del risk score por evento: es una **ventana de riesgo reciente**, no un contador histórico.
-   **Rango**: `0-100`. Estados: `low` (<30), `suspicious` (30-59), `high` (60-79), `critical` (80+).
-   **Acumulación**: suma el riesgo de cada evento del lote **incluyendo el +50 del enriquecimiento OTX**.
-   **Decaimiento**: `-5 puntos por hora` sin actividad, calculado en SQL (`julianday()`) contra Turso — un endpoint que deja de generar eventos vuelve solo a `low`, sin reset manual.
-   **Estado derivado**: `status` se calcula siempre a partir del score persistido, nunca se escribe a mano.

### 🗄️ Estrategia de Almacenamiento
Toda la persistencia vive en Turso (libSQL): `articles`, `assets`, `sensor_endpoints`,
`sensor_telemetry`, `sensor_detections`, `sensor_behavior_scores`, `sensor_alerts`,
`brand_protection_findings`, `otx_cache`, `cron_runs`. La telemetría de más de 30 días se borra
diariamente vía el cron `daily-jobs` (antes vivía en un `setInterval(24h)` dentro del proceso
Node, que no sobrevive entre invocaciones serverless).

### ⏱️ Trabajo asíncrono (Vercel Cron)
Plan Hobby de Vercel: máximo 2 crons, frecuencia diaria — por eso el trabajo está consolidado en
2 jobs (ver [vercel.json](vercel.json)):

-   **`daily-jobs`** (03:00 UTC): refresca los ~15 feeds RSS, refresca el caché OTX, limpia
    telemetría vieja. Todo rápido (fetch HTTP + escritura en Turso), cabe sin riesgo en una sola
    invocación.
-   **`scan-assets`** (04:00 UTC): escanea assets en orden "más antiguo primero" hasta agotar un
    presupuesto de tiempo (55s, con `maxDuration: 60` en `vercel.json`) — `scanDomain()` puede
    tardar 20s+ por dominio (crt.sh, cientos de variantes de typosquatting), así que en vez de
    recorrer todos los assets en una corrida, completa la rotación en pocos días.

Ambos jobs quedan registrados en la tabla `cron_runs` (éxito/fallo/detalle), consultable desde
`GET /api/cron/status`.

### 🔗 Apify (Deep Recon / Brand Protection)
-   `recon` y `facebook-recon` (actor `google-search-scraper`) siguen siendo llamadas bloqueantes
    (`.call()`) — decisión deliberada: son resultados que el usuario espera ver al hacer clic, y
    convertirlos a async requeriría UI de polling que hoy no existe.
-   `fb-scraper` (Brand Protection Monitor) usa `.start()` + webhook: dispara el actor y responde
    de inmediato; Apify llama después a `/api/webhooks/apify/brand-monitor` con el resultado,
    asegurado por `APIFY_WEBHOOK_SECRET`.

---

## 📊 Dashboard: Visualización de Analista
-   **Behavioral Timeline**: polling al servidor cada **3 segundos** mientras el modal de detalle de un endpoint está en el tab "Behavior", para dar sensación de tiempo real.
-   **Hardware Inventory**: visualiza hilos lógicos del CPU, discos duros locales y detalles del BIOS.
-   **Control Remoto**: el botón **"Forzar Conexión"** envía una señal al agente para que re-envíe su inventario completo de hardware y software inmediatamente.
-   **Feedback visual**: sistema de toasts (`src/components/Toast.jsx`) y modal de confirmación
    propio (`src/components/ConfirmDialog.jsx`) en vez de `alert()`/`confirm()` nativos del
    navegador; hook `useApiFetch` (`src/hooks/useApiFetch.js`) centraliza loading/error/data para
    las vistas que lo adoptan.

---

## 🔄 Flujo de Ciclo de Vida del Agente
1. `Inicio` ➔ `Obtener Serial BIOS` ➔ `POST /heartbeat` ➔ `ONLINE`.
2. `POST /sysinfo` (Hardware/Software) ➔ `Actualizar Dashboard`.
3. `Start Monitors` ➔ `Bucle /check (Comandos) cada poll_interval_seconds` (default 30s).
4. `Evento Detectado` ➔ `Cola de Telemetría` ➔ `POST /telemetry` ➔ `Dashboard Real-Time`.

---

## Fuera de alcance / pendiente

- `src/components/SOCLab/` es código huérfano: no está importado en `src/App.jsx`, se despliega
  igual pero queda inaccesible desde la UI. Conectarlo o eliminarlo es una decisión aparte.
- Mejoras de UX/UI del dashboard (responsive, accesibilidad, sistema de diseño) están listadas
  como backlog en [To_Do.md](To_Do.md).
