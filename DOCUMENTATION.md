# 🛡️ CyberIntel EC — EDR & Behavioral Analytics (v2.9.1)

Documentación técnica completa del sistema de detección y respuesta en endpoints (EDR) con análisis de comportamiento en tiempo real.

---

## 🏗️ Arquitectura del Sistema
El sistema se basa en un modelo de tres capas diseñado para ser ligero, portátil y extremadamente rápido:

1.  **Sensor Agente (Python 3.x)**: Script nativo que corre en los endpoints Windows. No requiere instalación de dependencias externas (`pip`).
2.  **Backend Server (Node.js/Express)**: Servidor central que gestiona la base de datos SQLite, procesa la telemetría y valida amenazas contra OTX (AlienVault).
3.  **Analyst Dashboard (React/Vite)**: Interfaz web de alta fidelidad que visualiza eventos en tiempo real y permite la gestión de dispositivos.

---

## 📡 Sensor Agente: Funcionamiento Interno
El agente v2.9.1 es multihilo y asíncrono, diseñado para no bloquear el sistema operativo del usuario.

### 🆔 Identidad y Persistencia
-   **Hardware-ID**: Utiliza el **Número de Serie del BIOS** como identificador primario (`agent_id`). Esto evita duplicados en la consola si el agente se reinstala o actualiza.
-   **Registro (Heartbeat)**: Al iniciar, el agente DEBE registrarse en el endpoint `/heartbeat`. Hasta que el servidor no confirme la conexión, el agente no inicia los monitores.

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

### 🔒 Capa de Seguridad (SSL/HTTPS)
Los dos puertos sirven la misma app Express pero **no exponen la misma superficie**:

-   **Puerto 3001 — Dashboard.** Escucha **sólo en `127.0.0.1`**. La API de gestión no tiene
    autenticación de usuario, así que no debe ser alcanzable desde la red.
-   **Puerto 8443 — Sensores.** Expuesto a la LAN, pero limitado por lista blanca a las rutas
    que el agente necesita (`heartbeat`, `sysinfo`, `check/:id`, `telemetry`, `detection`,
    `report`). Cualquier otra ruta responde 404: el canal de sensores no sirve la API de
    gestión ni el inventario de assets.
-   **Autenticación**: toda petición del agente lleva `AGENT_TOKEN`, comparado en **tiempo
    constante**. Si `AGENT_TOKEN` no está definido en `.env`, el canal **falla cerrado**
    (rechaza todo) en lugar de aceptar un valor por defecto conocido.
-   **TLS**: el agente **valida el certificado del servidor** contra una copia local de
    `server.cert`. `generate_certs.js` emite el certificado con SubjectAltName (localhost,
    hostname e IPs locales) para que la validación funcione al conectar por IP.

### 🧠 Inteligencia de Amenazas
-   **Integración OTX**: El servidor intercepta cada IP externa reportada y consulta la base de datos de AlienVault OTX para identificar IPs maliciosas de C2 (Command & Control).
-   **Puntuación de Riesgo (Risk Score)** — por evento:
    -   `0`: Informativo (Efímero, solo en RAM).
    -   `1-59`: Sospechoso (Almacenado en DB).
    -   `60+`: Crítico (Alerta inmediata).

### 📉 Score de Comportamiento del Endpoint
Distinto del risk score por evento: es una **ventana de riesgo reciente**, no un contador histórico.
-   **Rango**: `0-100`. Estados: `low` (<30), `suspicious` (30-59), `high` (60-79), `critical` (80+).
-   **Acumulación**: suma el riesgo de cada evento del lote **incluyendo el +50 del enriquecimiento OTX**.
-   **Decaimiento**: `-5 puntos por hora` sin actividad. Un endpoint que deja de generar eventos vuelve solo a `low`; no requiere reset manual (`reset_scores.js` queda como utilidad opcional).
-   **Estado derivado**: `status` se calcula siempre a partir del score persistido, nunca se escribe a mano.

### 🗄️ Estrategia de Almacenamiento
-   **Telemetría Volátil**: Los logs INFO (score 0) se almacenan en un buffer circular en **RAM** (máximo 50 por agente) para visualización en el timeline "en vivo". Nunca tocan el disco para evitar saturación.
-   **Persistencia**: Solo los eventos con riesgo real o detecciones confirmadas se guardan en la base de datos SQLite.

---

## 📊 Dashboard: Visualización de Analista
-   **Behavioral Timeline**: Realiza polling al servidor cada **3 segundos** para dar una sensación de "tiempo real".
-   **Hardware Inventory**: Visualiza hilos lógicos del CPU, Discos Duros locales y detalles del BIOS.
-   **Control Remoto**: El botón **"Forzar Conexión"** envía una señal al agente para que re-envíe su inventario completo de hardware y software inmediatamente.

---

## 🛠️ Configuración de Red y Puertos
-   **UI/API**: `http://127.0.0.1:3001` (sólo local)
-   **Sensor Connect**: `https://<host-o-ip>:8443`
-   **Requisito**: El servidor debe tener `server.key` y `server.cert` en la raíz para habilitar el canal de sensores.

### Puesta en marcha del canal de sensores
1.  **Generar certificados** (incluye los nombres/IPs del servidor en el SAN):
    `node generate_certs.js [nombre-o-ip-adicional ...]`
2.  **Generar el token compartido**:
    `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
    y ponerlo en `.env` como `AGENT_TOKEN=...`
3.  **En cada endpoint**, junto a `sensor.py`:
    -   copiar `server.cert` del servidor,
    -   copiar `agent.config.example.json` a `agent.config.json` y rellenar `server_url` y `agent_token`.
    -   Alternativa para despliegue masivo: variables de entorno `CYBERINTEL_SERVER_URL` y `CYBERINTEL_AGENT_TOKEN`, que tienen prioridad sobre el archivo.
4.  El agente **no arranca** si falta el token o el certificado, y lo dice en consola.

> `verify_tls: false` en `agent.config.json` desactiva la validación del certificado. Sólo para
> pruebas: reabre la puerta a un MITM en la red local.

---

## 🔄 Flujo de Ciclo de Vida del Agente
1. `Inicio` ➔ `Obtener Serial BIOS` ➔ `POST /heartbeat` ➔ `ONLINE`.
2. `POST /sysinfo` (Hardware/Software) ➔ `Actualizar Dashboard`.
3. `Start Monitors` ➔ `Bucle /check (Comandos) cada 5 seg`.
4. `Evento Detectado` ➔ `Cola de Telemetría` ➔ `POST /telemetry` ➔ `Dashboard Real-Time`.
