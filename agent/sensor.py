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
HOSTNAME = socket.gethostname()

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
        # Como Servicio de Windows (LocalSystem) no hay perfil de usuario ni
        # sesión interactiva: $env:LOCALAPPDATA\Google\Chrome no existe bajo
        # esa cuenta, así que el FileSystem Watcher de infostealers no tiene
        # nada que vigilar. Los otros dos monitores (procesos vía WMI, red)
        # sí funcionan igual bajo LocalSystem.
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
            res = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
            serial = res.stdout.strip()
            if serial and len(serial) > 3:
                return f"SN-{serial}"
        except:
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
        icons = {"INFO": " ", "CMD": "🔄", "ERROR": "❌", "SUCCESS": "✅"}
        icon = icons.get(level, " ")
        print(f"[{time.strftime('%H:%M:%S')}] [{level}] {icon} {msg}")

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
            elif "heartbeat" in endpoint or "sysinfo" in endpoint:
                print(f"[!] Error HTTP {e.code} ({endpoint})")
            return None
        except ssl.SSLError as e:
            self.log(f"Fallo de validación TLS: {e}", "ERROR")
            self.log("El certificado del servidor no coincide con el ca_cert configurado.", "ERROR")
            return None
        except Exception as e:
            if "heartbeat" in endpoint or "sysinfo" in endpoint:
                print(f"[!] Error de conexión ({endpoint}): {e}")
            return None

    def report_sysinfo(self):
        self.log("📋 Recolectando inventario de sistema...", "INFO")
        ps_command = """
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $cs = Get-CimInstance Win32_ComputerSystem | Select-Object -First 1
        $bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID) $([math]::Round($_.Size / 1GB, 0))GB" }
        $hw = @{
            os_name = $os.Caption; os_version = $os.Version; os_arch = $os.OSArchitecture
            cpu_name = $cpu.Name.Trim(); cpu_cores = $cpu.NumberOfCores; cpu_threads = $cpu.NumberOfLogicalProcessors
            ram_total_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            manufacturer = $cs.Manufacturer; model = $cs.Model; bios_serial = $bios.SerialNumber
            disks = ($disks -join ", ")
        }
        $sw = Get-ItemProperty HKLM:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\*, HKLM:\\\\Software\\\\Wow6432Node\\\\Microsoft\\Windows\\\\CurrentVersion\\\\Uninstall\\\\* -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } | Select-Object @{n='name';e={$_.DisplayName}}, @{n='version';e={$_.DisplayVersion}}, @{n='publisher';e={$_.Publisher}} | ConvertTo-Json -Compress
        Write-Output "HW_DATA:$($hw | ConvertTo-Json -Compress)"
        Write-Output "SW_DATA:$sw"
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_command], capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                hw, sw = {}, []
                for line in res.stdout.splitlines():
                    if line.startswith("HW_DATA:"): hw = json.loads(line.replace("HW_DATA:", ""))
                    if line.startswith("SW_DATA:"): sw = json.loads(line.replace("SW_DATA:", ""))
                self.send_to_server("sysinfo", {"hardware": hw, "software": sw})
                self.log("Inventario enviado exitosamente.", "SUCCESS")
        except Exception as e: self.log(f"Error en inventario: {e}", "ERROR")

    def command_loop(self):
        while self.running:
            try:
                res = self.send_to_server(f"check/{self.agent_id}", {})
                if res and res.get("force"):
                    self.log("Señal de 'Forzar Conexión' recibida. Actualizando...", "CMD")
                    self.report_sysinfo()
            except: pass
            time.sleep(self.poll_interval)

    def telemetry_sender_loop(self):
        while self.running:
            events = []
            try:
                ev = self.event_queue.get(timeout=1)
                events.append(ev)
                while not self.event_queue.empty() and len(events) < 20:
                    events.append(self.event_queue.get_nowait())
                if events:
                    self.send_to_server("telemetry", {"events": events})
            except queue.Empty: continue

    def run_ps_monitor(self, script):
        proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", script], stdout=subprocess.PIPE, text=True, bufsize=1)
        for line in iter(proc.stdout.readline, ''):
            if not self.running: break
            try:
                data = json.loads(line.strip())
                self.event_queue.put(data)
            except: pass

    def start_monitors(self):
        self.log("🚀 Iniciando WMI Process Watcher (v2.6 con MITRE)...", "INFO")
        p_script = """
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        Register-WmiEvent -Query $query -SourceIdentifier "ProcStart"
        while($true) {
            $e = Get-Event -SourceIdentifier "ProcStart" -ErrorAction SilentlyContinue
            if ($e) {
                $p = $e.SourceEventArgs.NewEvent.TargetInstance
                $cmd = "$($p.ExecutablePath) $($p.CommandLine)"
                $obj = @{ process_name=$p.ExecutablePath; risk_score=0; type="process"; description="Ejecución de proceso"; timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"); mitre_id=$null; mitre_tactic=$null; mitre_technique=$null; severity="LOW" }
                
                if ($cmd -match "whoami|systeminfo|net user|nltest|netstat|ipconfig|arp|route|tasklist|ping|tracert") {
                    $obj.risk_score=30; $obj.severity="MEDIUM"; $obj.description="Comando de Reconocimiento Detectado";
                    $obj.mitre_id="T1082"; $obj.mitre_tactic="Discovery"; $obj.mitre_technique="System Information Discovery"
                } elseif ($cmd -match "schtasks" -and ($cmd -match "/create" -or $cmd -match "/change")) {
                    $obj.risk_score=60; $obj.severity="HIGH"; $obj.description="Creación/Modificación de Tarea Programada";
                    $obj.mitre_id="T1053"; $obj.mitre_tactic="Persistence"; $obj.mitre_technique="Scheduled Task/Job"
                } elseif ($p.ExecutablePath -like "*\\\\Temp\\\\*") { 
                    $obj.risk_score=60; $obj.severity="HIGH"; $obj.description="Ejecución desde Temp"; 
                    $obj.mitre_id="T1059"; $obj.mitre_tactic="Execution"; $obj.mitre_technique="Command and Scripting Interpreter" 
                }
                
                Write-Output (ConvertTo-Json $obj -Compress)
                Remove-Event -SourceIdentifier "ProcStart"
            }
            Start-Sleep -Milliseconds 500
        }
        """
        threading.Thread(target=self.run_ps_monitor, args=(p_script,), daemon=True).start()

        if self.is_service:
            self.log("📂 FileSystem Watcher omitido: como Servicio de Windows (LocalSystem) no hay perfil de usuario que vigilar.", "INFO")
        else:
            self.log("📂 Iniciando FileSystem Watcher...", "INFO")
            f_script = """
            $p = "$env:LOCALAPPDATA\\\\Google\\\\Chrome\\\\User Data\\\\Default"
            if (Test-Path $p) {
                $w = New-Object System.IO.FileSystemWatcher; $w.Path = $p; $w.Filter = "Login Data"; $w.EnableRaisingEvents = $true
                $a = {
                    $obj = @{ type="file"; risk_score=80; severity="CRITICAL"; description="Acceso a base de datos de Chrome (Posible Infostealer)"; timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"); mitre_id="T1555.003"; mitre_tactic="Credential Access"; mitre_technique="Credentials from Web Browsers" };
                    Write-Output (ConvertTo-Json $obj -Compress)
                }
                Register-ObjectEvent $w "Changed" -Action $a | Out-Null
                while($true) { Start-Sleep -Seconds 5 }
            }
            """
            threading.Thread(target=self.run_ps_monitor, args=(f_script,), daemon=True).start()

        self.log("🌐 Iniciando Network Beaconing Monitor...", "INFO")
        n_script = """
        $reported = @{}
        while($true) {
            $conns = Get-NetTCPConnection -State Established | Where-Object { 
                $_.RemoteAddress -notlike '127.*' -and 
                $_.RemoteAddress -notlike '192.168.*' -and 
                $_.RemoteAddress -notlike '10.*' -and 
                $_.RemoteAddress -notlike '172.16.*' -and
                $_.RemoteAddress -notlike '0.0.0.0'
            } 
            if ($conns) {
                $conns | ForEach-Object {
                    $id = "$($_.RemoteAddress):$($_.RemotePort)"
                    # Solo reportar si es una conexión nueva o han pasado más de 6 HORAS
                    if (!$reported.ContainsKey($id) -or (Get-Date) -gt $reported[$id]) {
                        $obj = @{ 
                            dst_ip=$_.RemoteAddress; dst_port=$_.RemotePort; 
                            type="network"; risk_score=0; severity="LOW";
                            description="Conexión de red externa"; 
                            timestamp=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                            mitre_id="T1071"; mitre_tactic="Command and Control"; mitre_technique="Application Layer Protocol"
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
        threading.Thread(target=self.run_ps_monitor, args=(n_script,), daemon=True).start()

    def run(self):
        print(f"[*] CyberIntel Sensor v2.9 (REAL-TIME) - Activo en {HOSTNAME}")

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
        Corre bajo LocalSystem por defecto — ver la nota en __init__ sobre el
        FileSystem Watcher de Chrome, que queda deshabilitado en este modo."""
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
