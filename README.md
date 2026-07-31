# 🛡️ CyberIntel EC

Plataforma local de **inteligencia de amenazas y EDR** orientada al sector financiero de Ecuador.
Integra cuatro capacidades sobre un mismo servidor y un mismo panel:

| Capacidad | Qué hace |
|---|---|
| **Threat Intel** | Agrega y clasifica ~15 feeds RSS (globales, banca, alertas oficiales, noticias locales) por sector, severidad, región y actor de amenaza. |
| **OTX / AlienVault** | Pulses, indicadores, adversarios e industrias, con caché en memoria. |
| **Assets & Brand Protection** | Descubrimiento de subdominios desde 8 fuentes OSINT, verificación SPF/DMARC, generación de typosquatting y monitoreo de marca vía Apify. |
| **EDR / Endpoints** | Sensor Windows propio, telemetría en tiempo real, scoring de comportamiento y mapeo MITRE ATT&CK. |

---

## Arquitectura

```
┌──────────────────────┐        ┌───────────────────────────────┐
│  Dashboard React     │  /api  │  server.js (Express)          │
│  Vite :5173          │───────▶│  HTTP  :3001  (solo loopback) │
│  (proxy → :3001)     │        │  HTTPS :8443  (sensores/LAN)  │
└──────────────────────┘        └───────┬───────────────┬───────┘
                                        │               │
                              ┌─────────┴───┐   ┌───────┴────────┐
                              │ sensors.db  │   │ data.json      │
                              │  (SQLite)   │   │ assets.json    │
                              └─────────────┘   └────────────────┘
                                        ▲
                                        │ HTTPS :8443 (token + TLS verificado)
                              ┌─────────┴──────────────┐
                              │ agent/sensor.py        │
                              │ 3 monitores PowerShell │
                              └────────────────────────┘
```

El sensor es **Python 3 sin dependencias externas** (no requiere `pip install`). Se identifica por
el número de serie del BIOS y ejecuta tres monitores en paralelo: creación de procesos vía WMI,
acceso a archivos sensibles y beaconing de red.

---

## Requisitos

- Node.js 18+
- Python 3.8+ (solo en los endpoints monitoreados)
- Windows (el agente usa WMI y PowerShell)

## Puesta en marcha

```bash
npm install
cp .env.example .env        # rellenar las claves
node generate_certs.js      # certificados del canal de sensores
node server.js              # API en http://127.0.0.1:3001 y sensores en :8443
npm run dev                 # dashboard en http://localhost:5173
```

### Variables de entorno

| Variable | Obligatoria | Uso |
|---|---|---|
| `AGENT_TOKEN` | Sí | Autentica a los sensores. Sin ella el canal :8443 **falla cerrado**. |
| `OTX_API_KEY` | No | Integración con AlienVault OTX. Sin ella queda deshabilitada. |
| `APIFY_TOKEN` | No | Deep recon y brand protection. |

Generar el token compartido:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Desplegar un sensor

En cada endpoint, junto a `sensor.py`:

1. Copiar el `server.cert` del servidor.
2. Copiar `agent.config.example.json` a `agent.config.json` y rellenar `server_url` y `agent_token`.
   Alternativa para despliegue masivo: variables `CYBERINTEL_SERVER_URL` y `CYBERINTEL_AGENT_TOKEN`,
   que tienen prioridad sobre el archivo.
3. `python sensor.py`

El agente no arranca si falta el token o el certificado, e informa el motivo en consola.

---

## Modelo de seguridad

- **Separación de canales.** El puerto 3001 (dashboard, sin autenticación de usuario) escucha solo
  en `127.0.0.1`. El puerto 8443 está expuesto a la red pero limitado por lista blanca a las rutas
  que el agente necesita; cualquier otra ruta responde 404.
- **Autenticación de sensores.** Token compartido comparado en tiempo constante. Falla cerrado si
  no está configurado.
- **TLS verificado.** El agente valida el certificado del servidor contra una copia local;
  `generate_certs.js` emite el certificado con SubjectAltName para que la validación funcione al
  conectar por nombre o por IP.
- **Datos sensibles fuera del repositorio.** `.env`, `server.key`, `server.cert`,
  `agent/agent.config.json`, `sensors.db`, `data.json` y `assets.json` están en `.gitignore`.

> ⚠️ El dashboard no tiene autenticación de usuario. Está mitigado restringiéndolo a loopback;
> exponerlo a la red requiere añadir autenticación primero.

---

## Estructura

```
server.js                     API, feeds, OSINT, OTX, EDR y webhooks
agent/sensor.py               Sensor Windows (WMI, FileSystem, red)
src/App.jsx                   Dashboard (vistas Dashboard/Threats/Assets/Endpoints/Analysis)
src/components/SOCLab/        Portal de laboratorio SOC (escenarios guiados)
generate_certs.js             Certificados autofirmados con SAN
reset_scores.js               Utilidad para reiniciar scores de comportamiento
```

Documentación técnica detallada en [DOCUMENTATION.md](DOCUMENTATION.md).
