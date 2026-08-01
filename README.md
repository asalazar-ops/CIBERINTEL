# 🛡️ CyberIntel EC

Plataforma de **inteligencia de amenazas y EDR** orientada al sector financiero de Ecuador,
desplegada en Vercel (frontend + API + cron jobs) sobre una base de datos Turso (libSQL).
Integra cuatro capacidades sobre un mismo panel:

| Capacidad | Qué hace |
|---|---|
| **Threat Intel** | Agrega y clasifica ~15 feeds RSS (globales, banca, alertas oficiales, noticias locales) por sector, severidad, región y actor de amenaza. |
| **OTX / AlienVault** | Pulses, indicadores, adversarios e industrias, cacheados en base de datos. |
| **Assets & Brand Protection** | Descubrimiento de subdominios desde 8 fuentes OSINT, verificación SPF/DMARC, generación de typosquatting y monitoreo de marca vía Apify. |
| **EDR / Endpoints** | Sensor Windows propio, telemetría en tiempo real, scoring de comportamiento y mapeo MITRE ATT&CK. |

---

## Arquitectura

```
┌──────────────────────┐        ┌─────────────────────────────┐
│  Dashboard React     │  /api  │  Vercel Serverless Functions │
│  (Vite, servido      │───────▶│  api/index.js → server/app.js│
│  estático por Vercel)│        │  api/cron/*  (jobs diarios)  │
└──────────────────────┘        └───────┬──────────────┬──────┘
                                         │              │
                               ┌─────────┴───┐   ┌──────┴───────┐
                               │ Turso        │   │ Apify        │
                               │ (libSQL)     │   │ (webhook)     │
                               └──────────────┘   └───────────────┘
                                         ▲
                                         │ HTTPS público (token + CA pública)
                               ┌─────────┴──────────────┐
                               │ agent/sensor.py        │
                               │ 3 monitores PowerShell │
                               └────────────────────────┘
```

- **Todo el tráfico entra por un único dominio HTTPS de Vercel** — no hay puertos separados
  para dashboard y sensores (ver [Modelo de seguridad](#modelo-de-seguridad)).
- **`server/app.js`** contiene toda la app Express (rutas, middlewares); `api/index.js` la
  reexporta como función serverless. `server.js` sigue existiendo solo para correr localmente
  con `node server.js`.
- **`api/cron/*`** son funciones serverless independientes invocadas por Vercel Cron
  (`daily-jobs`: feeds + OTX + limpieza de telemetría; `scan-assets`: escaneo de dominios con
  presupuesto de tiempo). Ver [vercel.json](vercel.json) para el horario.
- El sensor es **Python 3 sin dependencias externas** (no requiere `pip install`). Se identifica
  por el número de serie del BIOS y ejecuta tres monitores en paralelo: creación de procesos vía
  WMI, acceso a archivos sensibles y beaconing de red.

---

## Requisitos

- Node.js 18+
- Cuenta de [Turso](https://turso.tech) (o dejar vacío para usar una base local embebida solo en desarrollo)
- Cuenta de [Vercel](https://vercel.com) para desplegar (plan Hobby es suficiente — ver nota de crons abajo)
- Python 3.8+ y Windows en cada endpoint monitoreado por el agente EDR

## Puesta en marcha (desarrollo local)

```bash
npm install
cp .env.example .env        # rellenar las claves (ver tabla abajo)
node server.js               # API en http://127.0.0.1:3001 y sensores en :8443
npm run dev                   # dashboard en http://localhost:5173
```

Sin `TURSO_DATABASE_URL`/`TURSO_AUTH_TOKEN`, el servidor usa un archivo local embebido
(`server/local.db`) — solo para desarrollo, nunca en producción.

### Variables de entorno

Todas documentadas con instrucciones de generación en [.env.example](.env.example). Resumen:

| Variable | Obligatoria | Uso |
|---|---|---|
| `TURSO_DATABASE_URL` / `TURSO_AUTH_TOKEN` | En producción | Base de datos. Sin ellas, fallback local solo para dev. |
| `AUTH_SECRET` | Sí | Firma las cookies de sesión del dashboard. Sin ella nadie puede iniciar sesión. |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD_HASH` | Sí | Credenciales del único usuario admin. Generar el hash con `node server/hash_password.js "contraseña"`. |
| `AGENT_TOKEN` | Sí | Autentica a los sensores EDR. Sin ella el canal de sensores **falla cerrado**. |
| `CRON_SECRET` | Sí (en Vercel) | Autentica las invocaciones de `/api/cron/*`. Vercel lo envía automático como `Authorization: Bearer`. |
| `APIFY_WEBHOOK_SECRET` / `APIFY_WEBHOOK_URL` | Sí para Brand Protection | Asegura el webhook de resultados asíncronos de Apify. |
| `OTX_API_KEY` | No | Integración con AlienVault OTX. Sin ella queda deshabilitada. |
| `APIFY_TOKEN` | No | Deep recon y brand protection. |
| `CORS_ORIGIN` | En producción | Dominio real de Vercel. |

Generar cualquier secreto:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Desplegar a Vercel

```bash
npx vercel link                 # vincular el proyecto
npx vercel env add <NOMBRE> <production|preview|development>   # una vez por variable/entorno
npx vercel deploy --prod
```

> **Plan Hobby**: limita a 2 cron jobs con frecuencia diaria — por eso `vercel.json` consolida
> el trabajo en `daily-jobs` + `scan-assets`, ambos una vez al día. Con plan Pro se puede volver
> a una frecuencia más alta.

### Desplegar un sensor EDR

En cada endpoint, junto a `sensor.py`:

1. Copiar `agent.config.example.json` a `agent.config.json`.
2. Rellenar `server_url` con el dominio de Vercel (`https://tu-app.vercel.app`) y `agent_token`
   con el mismo valor que `AGENT_TOKEN` en el servidor.
3. Dejar `ca_cert: null` — Vercel sirve un certificado de una CA pública, no hace falta pinnear
   nada localmente (`ca_cert` solo se usa para el `server.cert` autofirmado del modo local).
4. `python sensor.py`

El agente no arranca si falta el token o no puede validar el certificado, e informa el motivo en consola.

---

## Modelo de seguridad

- **Autenticación de dashboard.** Login único (sin tabla de usuarios) con sesión en cookie
  HttpOnly/Secure vía JWT (`server/auth.js`). Todas las rutas de gestión exigen sesión válida.
- **Autenticación de sensores.** Token compartido (`AGENT_TOKEN`) comparado en tiempo constante.
  Falla cerrado si no está configurado.
- **Autenticación de crons.** `/api/cron/*` exige `Authorization: Bearer $CRON_SECRET`, enviado
  automáticamente por Vercel Cron.
- **Webhook de Apify asegurado.** `/api/webhooks/apify/brand-monitor` exige `APIFY_WEBHOOK_SECRET`
  por cabecera; sin él, rechaza todo.
- **Aislamiento por credencial, no por puerto.** En Vercel todo entra por un único dominio HTTPS;
  el aislamiento entre el canal de sensores y las rutas de gestión lo dan `requireAuth` y
  `requireAgentToken`, no un puerto separado (el modo local con `node server.js` sí sigue abriendo
  dos puertos, pero es un detalle del entorno de desarrollo, no del modelo de seguridad real).
- **Datos sensibles fuera del repositorio.** `.env`, `agent/agent.config.json`,
  `server/local.db` y `.vercel/` están en `.gitignore`.

---

## Estructura

```
server/app.js                 App Express completa (rutas, middlewares, jobs)
server/db.js                  Cliente Turso/libSQL + shim de compatibilidad callback
server/auth.js                Login, sesión, requireAuth
server/store.js               Acceso a datos (articles, assets, otxCache, cronRuns)
server/migrate_to_turso.js    Migración one-shot desde SQLite/JSON locales a Turso
api/index.js                  Entrada serverless de Vercel (reexporta server/app.js)
api/cron/                     Funciones de cron (daily-jobs, scan-assets)
server.js                     Arranque local (dos puertos: dashboard + sensores)
agent/sensor.py               Sensor Windows (WMI, FileSystem, red)
src/App.jsx                   Dashboard (vistas Dashboard/Threats/Assets/Endpoints/Analysis)
src/hooks/useApiFetch.js      Hook centralizado de fetch (loading/error/data)
src/components/               Toast, ConfirmDialog, Spinner, ErrorBanner, Login
src/components/SOCLab/        Portal de laboratorio SOC (no enlazado desde App.jsx aún)
vercel.json                   Config de Vercel: rewrites, crons, maxDuration
```

Documentación técnica detallada del sensor/EDR en [DOCUMENTATION.md](DOCUMENTATION.md).
Mejoras de dashboard pendientes en [To_Do.md](To_Do.md).
