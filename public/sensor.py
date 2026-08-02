import os
import sys
import time
import json
import socket
import threading
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import ssl
import uuid
import queue
import logging
import logging.handlers
import hashlib
import re

import rules

# El logger usa emojis (❌, ✅, 🔗...) y la consola de Windows por defecto
# suele estar en cp1252, no UTF-8 — sin esto, cualquier log con emoji lanza
# UnicodeEncodeError y tumba el proceso (confirmado al probar sensor.exe
# compilado con PyInstaller en una consola cmd/PowerShell normal). Como
# Servicio de Windows no hay stdout real; reconfigure() falla en silencio
# en ese caso y no importa porque nada lee ese stream de todas formas.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# pywin32 solo es necesario para correr como Servicio de Windows (instalado
# por el instalador de Inno Setup). En modo consola (python sensor.py, sin
# argumentos) el agente funciona igual sin esta dependencia.
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

# Configuración
# Las rutas se resuelven contra la carpeta del ejecutable/script, no contra
# el directorio de trabajo: el agente suele lanzarse desde una tarea
# programada o un Servicio de Windows, no desde una terminal interactiva.
# Empaquetado con PyInstaller (--onefile), __file__ apunta al directorio
# temporal de extracción (sys._MEIPASS), NO a donde vive sensor.exe — sin
# este chequeo, el .exe nunca encontraría agent.config.json junto a él.
if getattr(sys, 'frozen', False):
    AGENT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(AGENT_DIR, "agent.config.json")
AGENT_ID_FILE = os.path.join(AGENT_DIR, "agent_id.txt")
QUEUE_FILE = os.path.join(AGENT_DIR, "queue.jsonl")
LOG_FILE = os.path.join(AGENT_DIR, "sensor.log")
HOSTNAME = socket.gethostname()

# Como Servicio de Windows no hay stdout real (nada lee ese stream), así que
# print() por sí solo deja al agente sin ningún rastro diagnosticable: la
# única señal que llegaba al Visor de Eventos era el LogErrorMsg de un fallo
# catastrófico del hilo principal, nunca la operación normal ni errores de
# los monitores individuales. Log rotativo a archivo junto al ejecutable,
# tanto en modo servicio como en modo consola (donde además se sigue
# imprimiendo, vía el StreamHandler de abajo).
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8'
)
_file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S'))
_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%H:%M:%S'))
logging.basicConfig(level=logging.INFO, handlers=[_file_handler, _stream_handler])
logger = logging.getLogger("sensor")

DEFAULT_CONFIG = {
    "server_url": "https://localhost:8443",
    "agent_token": "",
    # Vacío/null = confiar en la CA pública del sistema (Vercel usa un
    # certificado válido). Sólo hace falta apuntar a server.cert cuando el
    # servidor sigue siendo el autofirmado local.
    "ca_cert": "server.cert",
    "verify_tls": True,
    # Cada agente consulta /check en este intervalo. En serverless cada
    # consulta es una invocación de función facturable — a 5 s son ~17.000
    # invocaciones/día por agente. 30 s cumple igual la promesa de la doc
    # ("60 segundos o menos" para recibir la señal de 'Forzar Conexión').
    "poll_interval_seconds": 30
}

def load_config():
    """Lee agent.config.json; las variables de entorno tienen prioridad (despliegue por GPO)."""
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            # utf-8-sig: Notepad y `Set-Content -Encoding utf8` escriben BOM, y con
            # utf-8 a secas el archivo se descarta en silencio y el agente arranca
            # sin token.
            with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                cfg.update(json.load(f))
        except Exception as e:
            print(f"[!] agent.config.json no se pudo leer ({e}); se usan los valores por defecto.")
    cfg["server_url"] = os.environ.get("CYBERINTEL_SERVER_URL", cfg["server_url"])
    cfg["agent_token"] = os.environ.get("CYBERINTEL_AGENT_TOKEN", cfg["agent_token"])
    return cfg

class CyberIntelSensor:
    def __init__(self, is_service=False):
        self.config = load_config()
        self.server_url = self.config["server_url"].rstrip('/')
        self.token = self.config["agent_token"]
        self.agent_id = self.get_agent_id()
        self.ip = self.get_local_ip()
        self.running = True
        self.event_queue = queue.Queue()
        self.ssl_context = self.build_ssl_context()
        # Ya no condiciona el arranque de ningún monitor (el Credential Store
        # Watcher enumera perfiles bajo C:\Users\* directamente, funciona igual
        # bajo LocalSystem que en modo consola) — se conserva como metadato
        # informativo para logs/diagnóstico.
        self.is_service = is_service
        try:
            self.poll_interval = max(5, int(self.config.get("poll_interval_seconds", 30)))
        except (TypeError, ValueError):
            self.poll_interval = 30

    def _probe_handshake(self, ctx):
        """Intenta un handshake TLS real contra server_url con este contexto.
        Solo probar que create_default_context() no lanzó no basta: el error
        de OpenSSL 3.0.x en Windows ('EE certificate key too weak') ocurre
        recién durante el handshake, no al construir el contexto."""
        host = urllib.parse.urlsplit(self.server_url).hostname
        port = urllib.parse.urlsplit(self.server_url).port or 443
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass

    def build_ssl_context(self):
        """Valida el certificado del servidor. Antes se aceptaba cualquiera, lo que
        dejaba el canal abierto a un MITM en la red local."""
        if not self.config.get("verify_tls", True):
            self.log("verify_tls=false — el certificado del servidor NO se valida (sólo para pruebas).", "ERROR")
            return ssl._create_unverified_context()

        ca_cert = self.config.get("ca_cert")

        if not ca_cert:
            # Sin ca_cert: el servidor está detrás de un certificado emitido
            # por una CA pública (caso Vercel), así que basta con la cadena
            # de confianza del sistema — no hay nada que pinnear localmente.
            try:
                ctx = ssl.create_default_context()
                self._probe_handshake(ctx)
                return ctx
            except ssl.SSLCertVerificationError as e:
                if 'key too weak' not in str(e):
                    self.log(f"Fallo de verificación TLS: {e}", "ERROR")
                    return None
                # Bug conocido de OpenSSL 3.0.x en Windows: rechaza claves RSA
                # de tamaño normal (2048 bit, ej. certificados de Vercel/Google/
                # GitHub) por un chequeo de SECLEVEL mal aplicado durante el
                # handshake — no es un problema del certificado del servidor.
                # SECLEVEL=0 sigue verificando la cadena de confianza contra la
                # CA del sistema; solo desactiva ese chequeo de bits roto.
                self.log("OpenSSL de este equipo rechaza claves RSA estándar (bug conocido en Windows). Aplicando SECLEVEL=0 — la cadena de confianza se sigue verificando igual.", "ERROR")
                ctx = ssl.create_default_context()
                ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
                try:
                    self._probe_handshake(ctx)
                    return ctx
                except Exception as e2:
                    self.log(f"Persiste el fallo TLS incluso con SECLEVEL=0: {e2}", "ERROR")
                    return None
            except Exception as e:
                self.log(f"No se pudo establecer el contexto TLS del sistema: {e}", "ERROR")
                return None

        ca_path = ca_cert
        if not os.path.isabs(ca_path):
            ca_path = os.path.join(AGENT_DIR, ca_path)

        if not os.path.exists(ca_path):
            self.log(f"No se encontró el certificado de confianza en: {ca_path}", "ERROR")
            self.log("Copia el server.cert del servidor junto al agente (o deja ca_cert vacío para usar la CA del sistema).", "ERROR")
            return None

        try:
            return ssl.create_default_context(cafile=ca_path)
        except Exception as e:
            self.log(f"Certificado de confianza inválido: {e}", "ERROR")
            return None

    def get_agent_id(self):
        """Genera un ID único persistente basado en el Hardware del equipo"""
        try:
            # Intentamos obtener el Serial Number del BIOS (es único y permanente)
            cmd = "Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber"
            # Sin timeout, un PowerShell colgado (perfil corporativo, política de
            # ejecución interactiva, etc.) bloqueaba el arranque del sensor
            # indefinidamente — nunca llegaba a fallback al UUID de archivo.
            res = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=15)
            serial = res.stdout.strip()
            if serial and len(serial) > 3:
                return f"SN-{serial}"
        except Exception:
            pass

        # Si falla el BIOS, usamos el ID clásico guardado en archivo
        if os.path.exists(AGENT_ID_FILE):
            with open(AGENT_ID_FILE, 'r') as f: return f.read().strip()
        uid = str(uuid.uuid4())
        with open(AGENT_ID_FILE, 'w') as f: f.write(uid)
        return uid

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close()
            return ip
        except: return "127.0.0.1"

    def log(self, msg, level="INFO"):
        py_level = {"INFO": logging.INFO, "CMD": logging.INFO, "ERROR": logging.ERROR, "SUCCESS": logging.INFO}.get(level, logging.INFO)
        logger.log(py_level, msg)

    def send_to_server(self, endpoint, data):
        url = f"{self.server_url}/api/sensors/{endpoint}"
        try:
            payload = {
                **data,
                "agent_id": self.agent_id,
                "hostname": HOSTNAME,
                "ip": self.ip,
                "token": self.token,
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            }
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=10) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            # 403 es de configuración, no de red: merece un mensaje explícito.
            if e.code == 403:
                self.log("El servidor rechazó el token del agente (403). Revisa agent_token en agent.config.json.", "ERROR")
            else:
                self.log(f"Error HTTP {e.code} ({endpoint})", "ERROR")
            return None
        except ssl.SSLError as e:
            self.log(f"Fallo de validación TLS: {e}", "ERROR")
            self.log("El certificado del servidor no coincide con el ca_cert configurado.", "ERROR")
            return None
        except Exception as e:
            self.log(f"Error de conexión ({endpoint}): {e}", "ERROR")
            return None

    def report_sysinfo(self):
        self.log("📋 Recolectando inventario de sistema...", "INFO")
        # Antes solo leía HKLM\...\Uninstall (máquina completa) — se perdían
        # las apps instaladas por usuario (Chrome, Teams, Zoom suelen ir ahí),
        # justo las que más importan para el módulo de vulnerabilidades. Como
        # servicio (LocalSystem) HKCU es el del propio SYSTEM, no el de un
        # usuario real, así que se recorre HKEY_USERS enumerando los SID de
        # perfiles reales cargados (evita los pseudo-usuarios .DEFAULT/
        # _Classes). $os.Version da el build (ej. 10.0.22631) pero no la
        # revisión (UBR) — sin eso no se puede saber el nivel de parcheo real
        # del sistema operativo entre dos equipos con el mismo build.
        ps_command = """
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $cs = Get-CimInstance Win32_ComputerSystem | Select-Object -First 1
        $bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID) $([math]::Round($_.Size / 1GB, 0))GB" }
        $ubr = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -ErrorAction SilentlyContinue).UBR
        $osBuild = if ($ubr) { "$($os.Version).$ubr" } else { $os.Version }
        $hw = @{
            os_name = $os.Caption; os_version = $osBuild; os_arch = $os.OSArchitecture
            cpu_name = $cpu.Name.Trim(); cpu_cores = $cpu.NumberOfCores; cpu_threads = $cpu.NumberOfLogicalProcessors
            ram_total_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            manufacturer = $cs.Manufacturer; model = $cs.Model; bios_serial = $bios.SerialNumber
            disks = ($disks -join ", ")
        }

        $swPaths = @(
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
            "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
        )
        # HKEY_USERS solo tiene los hives de perfiles con sesión activa (o
        # cargados a mano). No es exhaustivo para usuarios que nunca iniciaron
        # sesión desde que arrancó el sensor, pero cubre el caso normal.
        Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-\\d+-\\d+-\\d+-\\d+$' } |
            ForEach-Object {
                $swPaths += "Registry::HKEY_USERS\\$($_.PSChildName)\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
            }
        $sw = Get-ItemProperty -Path $swPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } | Select-Object @{n='name';e={$_.DisplayName}}, @{n='version';e={$_.DisplayVersion}}, @{n='publisher';e={$_.Publisher}} |
            Sort-Object name, version -Unique | ConvertTo-Json -Compress

        $hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty HotFixID

        Write-Output "HW_DATA:$($hw | ConvertTo-Json -Compress)"
        Write-Output "SW_DATA:$sw"
        Write-Output "HOTFIX_DATA:$($hotfixes | ConvertTo-Json -Compress)"
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_command], capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                hw, sw, hotfixes = {}, [], []
                for line in res.stdout.splitlines():
                    if line.startswith("HW_DATA:"): hw = json.loads(line.replace("HW_DATA:", ""))
                    if line.startswith("SW_DATA:"): sw = json.loads(line.replace("SW_DATA:", ""))
                    if line.startswith("HOTFIX_DATA:"):
                        raw = line.replace("HOTFIX_DATA:", "")
                        parsed = json.loads(raw) if raw.strip() else []
                        # ConvertTo-Json colapsa un array de 1 elemento a un
                        # string suelto, no a una lista — normalizar aquí.
                        hotfixes = parsed if isinstance(parsed, list) else ([parsed] if parsed else [])
                # sw puede llegar como dict suelto (mismo colapso de PowerShell
                # con un solo resultado) en vez de lista.
                if isinstance(sw, dict):
                    sw = [sw]
                self.send_to_server("sysinfo", {"hardware": hw, "software": sw, "hotfixes": hotfixes})
                self.log(f"Inventario enviado exitosamente ({len(sw)} apps, {len(hotfixes)} hotfixes).", "SUCCESS")
        except Exception as e: self.log(f"Error en inventario: {e}", "ERROR")

    def command_loop(self):
        while self.running:
            try:
                res = self.send_to_server(f"check/{self.agent_id}", {})
                if res and res.get("force"):
                    self.log("Señal de 'Forzar Conexión' recibida. Actualizando...", "CMD")
                    self.report_sysinfo()
            except Exception as e:
                self.log(f"Error en command_loop: {e}", "ERROR")
            time.sleep(self.poll_interval)

    def heartbeat_loop(self):
        """El único heartbeat original era al arrancar: un sensor corriendo días
        sin reiniciar nunca refrescaba explícitamente su estado ONLINE fuera de
        /check (que sí lo hace, pero solo si el servidor le pidió reconectar).
        Este loop es una señal de vida independiente, cada 5 minutos."""
        while self.running:
            time.sleep(300)
            if not self.running:
                break
            self.send_to_server("heartbeat", {})

    def _load_persisted_queue(self):
        """Recupera eventos que quedaron en disco de una corrida anterior (el
        proceso murió, o el servidor estuvo caído) y los reencola para reintento."""
        if not os.path.exists(QUEUE_FILE):
            return
        try:
            with open(QUEUE_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            os.remove(QUEUE_FILE)
            recovered = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.event_queue.put(json.loads(line))
                    recovered += 1
                except json.JSONDecodeError:
                    continue
            if recovered:
                self.log(f"Recuperados {recovered} eventos pendientes de la sesión anterior.", "INFO")
        except Exception as e:
            self.log(f"No se pudo recuperar la cola persistida: {e}", "ERROR")

    def _persist_events(self, events):
        """Vuelca eventos a disco cuando el envío falla, para no perderlos si el
        proceso termina antes del siguiente reintento. Cap de tamaño: un enlace
        caído por horas no debe llenar el disco — se prioriza lo más reciente."""
        try:
            MAX_QUEUE_BYTES = 5 * 1024 * 1024
            with open(QUEUE_FILE, 'a', encoding='utf-8') as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")
            if os.path.exists(QUEUE_FILE) and os.path.getsize(QUEUE_FILE) > MAX_QUEUE_BYTES:
                with open(QUEUE_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                # Se descarta la mitad más antigua, no el archivo entero: sigue
                # habiendo señal reciente que enviar en cuanto vuelva la red.
                with open(QUEUE_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(lines[len(lines) // 2:])
        except Exception as e:
            self.log(f"No se pudo persistir la cola de telemetría: {e}", "ERROR")

    def telemetry_sender_loop(self):
        self._load_persisted_queue()
        backoff = 5
        while self.running:
            events = []
            try:
                ev = self.event_queue.get(timeout=1)
                events.append(ev)
                while not self.event_queue.empty() and len(events) < 20:
                    events.append(self.event_queue.get_nowait())
            except queue.Empty:
                continue

            if not events:
                continue

            # send_to_server ya traga sus propias excepciones y devuelve None en
            # fallo — antes, ese None hacía descartar el lote entero en
            # silencio. Ahora se persiste a disco y se reintenta con backoff.
            result = self.send_to_server("telemetry", {"events": events})
            if result is None:
                self._persist_events(events)
                self.log(f"Fallo al enviar {len(events)} eventos; persistidos para reintento en {backoff}s.", "ERROR")
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
            else:
                backoff = 5

    def _score_and_hash(self, category, event):
        """Evalúa un evento crudo contra agent/rules.py y le adjunta el
        resultado. Antes la decisión de riesgo/MITRE vivía hardcodeada dentro
        del script de PowerShell (if/elseif mutuamente excluyentes, sin poder
        testear nada fuera de Windows); ahora los monitores solo recolectan
        datos crudos y esto es lo único que decide severidad y técnica.

        Un evento puede disparar varias reglas: se toma el score más alto para
        risk_score/severity (así el evento no se pierde en el filtro de
        persistencia del servidor, que corta en risk_score>=30), pero se
        adjuntan TODAS las técnicas que aplicaron en `matched_rules` — antes,
        con el esquema if/elseif, un whoami.exe corriendo desde \\Temp\\ solo
        se contaba como una cosa, nunca como las dos."""
        matches = rules.evaluate(category, event)
        if not matches:
            event.setdefault('risk_score', 0)
            event.setdefault('severity', 'LOW')
            event.setdefault('mitre_id', None)
            event.setdefault('mitre_tactic', None)
            event.setdefault('mitre_technique', None)
            return event

        best = max(matches, key=lambda m: m['risk_score'])
        event['risk_score'] = best['risk_score']
        event['severity'] = best['severity']
        event['mitre_id'] = best['mitre_id']
        event['mitre_tactic'] = best['mitre_tactic']
        event['mitre_technique'] = best['mitre_technique']
        event['description'] = best['description']
        event['matched_rules'] = [m['rule_id'] for m in matches]
        # Técnicas secundarias: si el evento disparó más de una regla, el
        # servidor/UI puede mostrarlas todas aunque solo una determine el score.
        if len(matches) > 1:
            event['additional_techniques'] = [
                {"mitre_id": m['mitre_id'], "mitre_tactic": m['mitre_tactic'], "mitre_technique": m['mitre_technique']}
                for m in matches if m is not best
            ]
        return event

    def _hash_if_suspicious(self, event):
        """SHA256 del binario, calculado SOLO cuando la regla ya disparó o la
        ruta es de por sí sospechosa (Temp/AppData/Downloads) — hashear cada
        proceso que arranca en el sistema sería carísimo en CPU/IO para una
        señal que casi siempre no hace falta. Habilita la correlación por hash
        contra threat intel (antes código muerto: el agente nunca enviaba
        file_hash) y contra MalwareBazaar en la Fase 3."""
        path = event.get('process_name')
        if not path or not os.path.isfile(path):
            return event
        suspicious = event.get('risk_score', 0) > 0 or re.search(r'\\(temp|appdata|downloads)\\', path.lower())
        if not suspicious:
            return event
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                # Cap de 20MB: un hash completo de binarios grandes (instaladores,
                # etc.) bloquearía el hilo del monitor por segundos; para
                # correlación de IOC basta con un hash estable del contenido,
                # así que se trunca en vez de saltarse el hash entero.
                h.update(f.read(20 * 1024 * 1024))
            event['file_hash'] = h.hexdigest()
        except Exception:
            pass
        return event

    def run_ps_monitor(self, name, category, script):
        """Supervisa el subproceso PowerShell: antes, si moría (crash, script que
        termina, etc.) el hilo se acababa en silencio y esa fuente de telemetría
        dejaba de existir sin que nada lo reflejara — el sensor seguía
        reportándose ONLINE igual. Ahora se reinicia con backoff y se registra
        el motivo, incluyendo stderr (antes no se capturaba en absoluto).

        `category` enruta el evento crudo al ruleset correcto de agent/rules.py
        antes de encolarlo — los scripts de PowerShell ya no deciden nada."""
        backoff = 5
        while self.running:
            proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-Command", script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
            start = time.time()
            try:
                for line in iter(proc.stdout.readline, ''):
                    if not self.running:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if category:
                            data = self._score_and_hash(category, data)
                            if category == 'process':
                                data = self._hash_if_suspicious(data)
                        self.event_queue.put(data)
                    except json.JSONDecodeError:
                        self.log(f"Monitor '{name}': línea no-JSON descartada: {line[:200]}", "ERROR")
            finally:
                if proc.poll() is None:
                    proc.terminate()
                stderr_output = ''
                try:
                    stderr_output = (proc.stderr.read() or '').strip()
                except Exception:
                    pass

            if not self.running:
                break

            uptime = time.time() - start
            detail = f" — stderr: {stderr_output[:500]}" if stderr_output else ''
            self.log(f"Monitor '{name}' terminó (uptime {uptime:.0f}s){detail}. Reiniciando en {backoff}s.", "ERROR")
            time.sleep(backoff)
            # Un monitor que corrió sano por un rato y luego cayó no es lo mismo
            # que uno que revienta al instante en bucle — solo el segundo caso
            # amerita backoff creciente.
            backoff = min(backoff * 2, 60) if uptime < 30 else 5

    def start_monitors(self):
        self.log("🚀 Iniciando WMI Process Watcher...", "INFO")
        # Recolector "tonto": ya no decide risk_score ni MITRE (eso lo hace
        # agent/rules.py en Python, vía _score_and_hash en run_ps_monitor).
        # Ahora emite datos crudos enriquecidos — antes solo mandaba
        # process_name; sin PPID/padre/usuario/cmdline por separado no había
        # con qué evaluar reglas como "Office lanzó un intérprete de comandos"
        # ni qué mostrar como "Parent" en el timeline (esa columna siempre
        # llegaba null desde el servidor, ver server/app.js).
        p_script = """
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        Register-WmiEvent -Query $query -SourceIdentifier "ProcStart"
        while($true) {
            $e = Get-Event -SourceIdentifier "ProcStart" -ErrorAction SilentlyContinue
            if ($e) {
                $p = $e.SourceEventArgs.NewEvent.TargetInstance
                $parentName = $null
                try {
                    $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction Stop
                    if ($parentProc) { $parentName = $parentProc.Name }
                } catch {}
                $userName = $null
                try {
                    $ownerInfo = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                    if ($ownerInfo.ReturnValue -eq 0) { $userName = "$($ownerInfo.Domain)\\$($ownerInfo.User)" }
                } catch {}
                $obj = @{
                    type="process"; process_name=$p.ExecutablePath; cmdline=$p.CommandLine;
                    pid=$p.ProcessId; parent_pid=$p.ParentProcessId; parent_name=$parentName; user=$userName;
                    timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
                Write-Output (ConvertTo-Json $obj -Compress)
                Remove-Event -SourceIdentifier "ProcStart"
            }
            Start-Sleep -Milliseconds 500
        }
        """
        threading.Thread(target=self.run_ps_monitor, args=("process", "process", p_script), daemon=True).start()

        # Antes solo vigilaba $env:LOCALAPPDATA del usuario que lanzó el proceso
        # — bajo LocalSystem (que es como corre el servicio instalado, el
        # despliegue real) esa variable no apunta a ningún perfil de usuario, así
        # que la detección más severa del sensor (CRITICAL/80, infostealer)
        # nunca se disparaba en producción. Ahora enumera los perfiles reales en
        # C:\Users\* y vigila Chrome, Edge y Firefox en cada uno.
        self.log("📂 Iniciando Credential Store Watcher...", "INFO")
        f_script = """
        $watchers = @()
        $targets = @(
            @{ browser = "Chrome"; sub = "AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default"; file = "Login Data" },
            @{ browser = "Edge"; sub = "AppData\\\\Local\\\\Microsoft\\\\Edge\\\\User Data\\\\Default"; file = "Login Data" },
            @{ browser = "Firefox"; sub = "AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles"; file = "*.default*\\\\logins.json" }
        )
        $profiles = Get-ChildItem "C:\\\\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

        foreach ($profile in $profiles) {
            foreach ($t in $targets) {
                $full = Join-Path $profile.FullName $t.sub
                if (Test-Path $full) {
                    $w = New-Object System.IO.FileSystemWatcher
                    $w.Path = $full
                    $w.Filter = $t.file
                    $w.IncludeSubdirectories = $true
                    $w.EnableRaisingEvents = $true
                    # $using: es sintaxis de Invoke-Command/jobs remotos, no de
                    # scriptblocks de Register-ObjectEvent — ese -Action corre en
                    # el runspace de eventos, que no ve variables del scope
                    # externo salvo que se le pasen explícitas vía -MessageData.
                    $a = {
                        $ctx = $Event.MessageData
                        $obj = @{ type="file"; target_path=$Event.SourceEventArgs.FullPath; risk_score=80; severity="CRITICAL"; description="Acceso a base de datos de credenciales de $($ctx.Browser) (usuario $($ctx.User)) — posible infostealer"; timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"); mitre_id="T1555.003"; mitre_tactic="Credential Access"; mitre_technique="Credentials from Web Browsers" };
                        Write-Output (ConvertTo-Json $obj -Compress)
                    }
                    Register-ObjectEvent $w "Changed" -Action $a -MessageData @{ Browser = $t.browser; User = $profile.Name } | Out-Null
                    $watchers += $w
                }
            }
        }
        if ($watchers.Count -eq 0) {
            Write-Error "Ningún perfil de navegador encontrado bajo C:\\Users — nada que vigilar."
            exit 1
        }
        while($true) { Start-Sleep -Seconds 5 }
        """
        threading.Thread(target=self.run_ps_monitor, args=("credential_store", None, f_script), daemon=True).start()

        self.log("🌐 Iniciando Network Beaconing Monitor...", "INFO")
        # OwningProcess ahora se resuelve a nombre de proceso (antes no se
        # capturaba: no había forma de saber qué proceso hizo la conexión).
        # Filtro RFC1918 corregido: "172.16.*" solo cubría 172.16.0.0/16 de los
        # 16 bloques /16 que en realidad forman 172.16.0.0/12 (172.16–172.31).
        n_script = """
        $reported = @{}
        while($true) {
            $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
                $octets = $_.RemoteAddress -split '\\.'
                $_.RemoteAddress -notlike '127.*' -and
                $_.RemoteAddress -notlike '169.254.*' -and
                $_.RemoteAddress -notlike '192.168.*' -and
                $_.RemoteAddress -notlike '10.*' -and
                -not ($octets[0] -eq '172' -and [int]$octets[1] -ge 16 -and [int]$octets[1] -le 31) -and
                $_.RemoteAddress -ne '0.0.0.0'
            }
            if ($conns) {
                $conns | ForEach-Object {
                    $id = "$($_.RemoteAddress):$($_.RemotePort)"
                    # Solo reportar si es una conexión nueva o han pasado más de 6 HORAS
                    if (!$reported.ContainsKey($id) -or (Get-Date) -gt $reported[$id]) {
                        $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { "desconocido" }
                        $obj = @{
                            dst_ip=$_.RemoteAddress; dst_port=$_.RemotePort; process_name=$procName;
                            type="network"; risk_score=0; severity="LOW";
                            description="Conexión de red externa ($procName)";
                            timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        }
                        Write-Output (ConvertTo-Json $obj -Compress)
                        $reported[$id] = (Get-Date).AddHours(6)
                    }
                }
            }
            # Limpiar caché de conexiones viejas para no saturar memoria
            if ($reported.Count -gt 100) { $reported = @{} }
            Start-Sleep -Seconds 30
        }
        """
        threading.Thread(target=self.run_ps_monitor, args=("network", None, n_script), daemon=True).start()

        self.log("🔑 Iniciando Registry Persistence Watcher...", "INFO")
        # T1547.001 — persistencia vía claves Run/RunOnce. Vigila tanto HKLM
        # (afecta a todos los usuarios) como HKCU del usuario actual; bajo
        # LocalSystem (modo servicio) HKCU es el del propio SYSTEM, pero HKLM
        # sigue siendo la superficie relevante para malware que busca
        # persistencia a nivel de máquina.
        r_script = """
        $paths = @(
            "HKLM:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            "HKLM:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
            "HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            "HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce"
        )
        # WMI __RegistryValueChangeEvent exige la clave completa por separado
        # (no admite comodines de ruta), así que se registra un watcher por
        # cada una de las 4 rutas.
        $i = 0
        foreach ($p in $paths) {
            if (-not (Test-Path $p)) { continue }
            $hive = if ($p -like "HKLM:*") { "HKEY_LOCAL_MACHINE" } else { "HKEY_CURRENT_USER" }
            $subkey = ($p -replace '^HK(LM|CU):\\\\', '') -replace '\\\\', '\\\\\\\\'
            $query = "SELECT * FROM RegistryValueChangeEvent WHERE Hive='$hive' AND KeyPath='$subkey'"
            try {
                Register-WmiEvent -Namespace root\\default -Query $query -SourceIdentifier "RegWatch$i" -ErrorAction Stop | Out-Null
                $i++
            } catch {}
        }
        if ($i -eq 0) {
            Write-Error "No se pudo registrar ningún watcher de registro."
            exit 1
        }
        while ($true) {
            for ($j = 0; $j -lt $i; $j++) {
                $ev = Get-Event -SourceIdentifier "RegWatch$j" -ErrorAction SilentlyContinue
                if ($ev) {
                    $obj = @{ type="registry"; key_path=$paths[$j]; timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") }
                    Write-Output (ConvertTo-Json $obj -Compress)
                    Remove-Event -SourceIdentifier "RegWatch$j"
                }
            }
            Start-Sleep -Milliseconds 800
        }
        """
        threading.Thread(target=self.run_ps_monitor, args=("registry", "registry", r_script), daemon=True).start()

        self.log("⚙️ Iniciando Service Creation Watcher...", "INFO")
        # T1543.003 — creación de un nuevo Servicio de Windows. WITHIN 2 porque
        # __InstanceCreationEvent sobre Win32_Service es más costoso de evaluar
        # que sobre Win32_Process; 1s de granularidad no aporta aquí (crear un
        # servicio no es una acción de alta frecuencia como sí lo es arrancar
        # procesos).
        s_script = """
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Service'"
        Register-WmiEvent -Query $query -SourceIdentifier "SvcCreate"
        while($true) {
            $e = Get-Event -SourceIdentifier "SvcCreate" -ErrorAction SilentlyContinue
            if ($e) {
                $s = $e.SourceEventArgs.NewEvent.TargetInstance
                $obj = @{ type="service"; service_name=$s.Name; display_name=$s.DisplayName; path_name=$s.PathName; start_mode=$s.StartMode; timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") }
                Write-Output (ConvertTo-Json $obj -Compress)
                Remove-Event -SourceIdentifier "SvcCreate"
            }
            Start-Sleep -Milliseconds 800
        }
        """
        threading.Thread(target=self.run_ps_monitor, args=("service", "service", s_script), daemon=True).start()

    def run(self):
        self.log(f"CyberIntel Sensor v3.0 — Activo en {HOSTNAME}", "INFO")

        # Fallar temprano y con un motivo claro es preferible a arrancar los
        # monitores y que cada envío se rechace en silencio.
        if not self.token:
            self.log("No hay agent_token configurado. Edita agent.config.json o define CYBERINTEL_AGENT_TOKEN.", "ERROR")
            return
        if self.ssl_context is None:
            self.log("No se pudo construir el contexto TLS. El agente no arranca.", "ERROR")
            return

        self.log(f"🔗 Registrando sensor en {self.server_url}...", "INFO")
        if self.send_to_server("heartbeat", {}):
            self.log("Conexión establecida con el servidor.", "SUCCESS")
            self.report_sysinfo()
            self.start_monitors()
            threading.Thread(target=self.command_loop, daemon=True).start()
            threading.Thread(target=self.telemetry_sender_loop, daemon=True).start()
            threading.Thread(target=self.heartbeat_loop, daemon=True).start()
            try:
                while self.running: time.sleep(1)
            except KeyboardInterrupt: self.running = False
        else:
            self.log("No se pudo establecer conexión inicial. Verifica server_url, el token y el certificado.", "ERROR")

if HAS_PYWIN32:
    class CyberIntelWindowsService(win32serviceutil.ServiceFramework):
        """Envoltorio de Servicio de Windows sobre CyberIntelSensor. Instalado
        por el instalador (Inno Setup) vía:
            sensor.exe install
            sensor.exe start
        Corre bajo LocalSystem por defecto."""
        _svc_name_ = "CyberIntelEDRSensor"
        _svc_display_name_ = "CyberIntel EC — Sensor EDR"
        _svc_description_ = "Monitoreo de procesos, red y detección de amenazas para CyberIntel EC."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.sensor = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.sensor:
                self.sensor.running = False
            win32event.SetEvent(self.stop_event)

        def _start_sensor(self):
            # Construir CyberIntelSensor hace I/O de red real (build_ssl_context
            # prueba un handshake TLS contra el servidor) — si esto corriera en
            # SvcDoRun antes de reportar RUNNING, el Service Control Manager
            # puede agotar su timeout de arranque y matar el servicio (visto en
            # producción: "El servicio no respondió a tiempo a la solicitud de
            # inicio"). Por eso se reporta RUNNING primero y esto corre después,
            # en un hilo aparte que no bloquea el arranque.
            #
            # Sin consola (modo servicio real, no `sensor.exe debug`), un error
            # aquí no tiene dónde imprimirse — sin este try/except quedaría
            # silencioso: el servicio se ve "Running" en el SCM pero el sensor
            # nunca conecta y no queda ningún rastro de por qué.
            try:
                self.sensor = CyberIntelSensor(is_service=True)
                self.sensor.run()
            except Exception as e:
                servicemanager.LogErrorMsg(f"CyberIntelEDRSensor: fallo irrecuperable en el hilo del sensor: {e}")

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            threading.Thread(target=self._start_sensor, daemon=True).start()
            # Confirmar RUNNING de inmediato: sin esto el SCM considera que el
            # servicio no respondió y lo da por fallido, aunque el sensor
            # termine conectando bien poco después.
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


if __name__ == "__main__":
    # OJO: cuando el Service Control Manager lanza este .exe como servicio ya
    # instalado, lo hace SIN argumentos — igual que al correrlo a mano en
    # consola. sys.argv no sirve para distinguir ambos casos (bug real
    # encontrado probando esto: el servicio se quedaba colgado en "Iniciando"
    # hasta agotar el timeout del SCM porque el proceso arrancaba en modo
    # consola normal en vez de entrar al framework de servicio).
    #
    # win32serviceutil.HandleCommandLine es solo la interfaz de comandos
    # (install/start/stop/debug) — cuando el SCM ya lanzó el proceso, ese NO
    # es el punto de entrada correcto (con cero argumentos hace sys.exit
    # imprimiendo el "usage"). El mecanismo real es
    # servicemanager.StartServiceCtrlDispatcher(), que solo tiene éxito
    # cuando quien lanzó el proceso fue efectivamente el SCM; si lo lanzó un
    # humano en una consola, falla con ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
    # y ahí sí cae a modo consola normal.
    if HAS_PYWIN32 and len(sys.argv) == 1:
        try:
            servicemanager.PrepareToHostSingle(CyberIntelWindowsService)
            servicemanager.Initialize()
            servicemanager.StartServiceCtrlDispatcher()
        except Exception:
            # No lo lanzó el SCM: correr en modo consola normal, igual que
            # siempre (desarrollo, pruebas, o el analista prefiere correrlo
            # a mano sin instalar el servicio).
            CyberIntelSensor().run()
    elif HAS_PYWIN32:
        # Con argumentos explícitos: comandos de pywin32
        # (install/start/stop/remove/debug), los mismos que invoca el
        # instalador de Inno Setup.
        win32serviceutil.HandleCommandLine(CyberIntelWindowsService)
    else:
        CyberIntelSensor().run()
