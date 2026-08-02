# Motor de reglas de detección — evalúa eventos crudos que ya vienen de los
# monitores PowerShell (que ahora solo recolectan y no deciden nada) y les
# asigna 0, 1 o varias técnicas MITRE ATT&CK. Vive como datos (lista de dicts),
# no como código embebido en strings de PowerShell: antes cada regla nueva
# significaba editar un script embebido con triple escape de backslashes y
# quotes, sin poder testear nada fuera de una máquina Windows real. Aquí se
# puede importar y probar con `python -c "import rules; ..."` en cualquier
# sistema operativo.
#
# Cada regla es independiente y NO exclusiva: un evento puede disparar varias
# reglas a la vez (antes las 3 reglas de proceso eran un if/elseif, así que un
# whoami.exe corriendo desde \Temp\ solo contaba como "reconocimiento" y nunca
# como "ejecución sospechosa" — se perdía la segunda señal).

import re


def _rx(pattern):
    return re.compile(pattern, re.IGNORECASE)


# Cada regla: {id, applies_to (tipo de evento crudo), match(event) -> bool,
# mitre_id, mitre_tactic, mitre_technique, severity, risk_score, description}.
# match() recibe el dict crudo del evento (campos como cmdline, process_name,
# parent_name, target_path, etc. — ver PROCESS_EVENT_FIELDS más abajo) y debe
# ser puro / sin side effects: se llama para cada evento contra cada regla de
# su categoría.

_RECON_RX = _rx(r'\b(whoami|systeminfo|nltest|netstat|ipconfig|arp|route|tasklist|ping|tracert)\b|\bnet\s+user\b')
_SCHTASKS_RX = _rx(r'\bschtasks\b')
_SCHTASKS_ACTION_RX = _rx(r'/create|/change')
_TEMP_PATH_RX = _rx(r'\\temp\\')
_ENCODED_PS_RX = _rx(r'-enc(odedcommand)?\b|frombase64string|\biex\b|downloadstring')
_LOLBIN_RX = _rx(
    r'certutil.*(-decode|-urlcache)'
    r'|\bmshta\b'
    r'|regsvr32.*(/i:https?|/i:ftp)'
    r'|rundll32.*javascript:'
    r'|bitsadmin.*\/transfer'
    r'|wmic\s+process\s+call\s+create'
    r'|msiexec.*\/i\s*https?'
)
_LSASS_RX = _rx(r'\bprocdump\b.*lsass|comsvcs\.dll.*minidump|lsass\.exe.*(dump|minidump)')
_INHIBIT_RECOVERY_RX = _rx(r'vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s+no')
_DISABLE_DEFENSES_RX = _rx(
    r'set-mppreference.*-disable'
    r'|netsh\s+advfirewall.*set.*state\s+off'
    r'|stop-service.*windefend'
    r'|sc\s+(stop|config)\s+windefend'
)
_ACCOUNT_MANIPULATION_RX = _rx(r'net\s+user\s+\S+\s+\S*\s*/add|net\s+localgroup\s+administrators\s+\S+\s+/add')
_DOWNLOAD_TOOL_RX = _rx(r'\b(curl|wget)\b.*https?://|certutil.*-urlcache.*https?://')

_OFFICE_PARENTS = {'winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe'}
_SUSPICIOUS_CHILDREN = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}


def _process_cmdline(ev):
    return f"{ev.get('process_name') or ''} {ev.get('cmdline') or ''}"


PROCESS_RULES = [
    {
        "id": "recon_command",
        "match": lambda ev: bool(_RECON_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1082", "mitre_tactic": "Discovery", "mitre_technique": "System Information Discovery",
        "severity": "MEDIUM", "risk_score": 30, "description": "Comando de Reconocimiento Detectado",
    },
    {
        "id": "scheduled_task",
        "match": lambda ev: bool(_SCHTASKS_RX.search(_process_cmdline(ev))) and bool(_SCHTASKS_ACTION_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1053", "mitre_tactic": "Persistence", "mitre_technique": "Scheduled Task/Job",
        "severity": "HIGH", "risk_score": 60, "description": "Creación/Modificación de Tarea Programada",
    },
    {
        "id": "exec_from_temp",
        "match": lambda ev: bool(_TEMP_PATH_RX.search((ev.get('process_name') or '').lower())),
        "mitre_id": "T1059", "mitre_tactic": "Execution", "mitre_technique": "Command and Scripting Interpreter",
        "severity": "HIGH", "risk_score": 60, "description": "Ejecución desde Temp",
    },
    {
        "id": "encoded_powershell",
        "match": lambda ev: bool(_ENCODED_PS_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1059.001", "mitre_tactic": "Execution", "mitre_technique": "PowerShell",
        "severity": "HIGH", "risk_score": 65, "description": "PowerShell con comando codificado/descarga en memoria",
    },
    {
        "id": "lolbin_abuse",
        "match": lambda ev: bool(_LOLBIN_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1218", "mitre_tactic": "Defense Evasion", "mitre_technique": "System Binary Proxy Execution",
        "severity": "HIGH", "risk_score": 65, "description": "Uso sospechoso de binario del sistema (LOLBin)",
    },
    {
        "id": "lsass_access",
        "match": lambda ev: bool(_LSASS_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1003.001", "mitre_tactic": "Credential Access", "mitre_technique": "LSASS Memory",
        "severity": "CRITICAL", "risk_score": 90, "description": "Posible volcado de memoria de LSASS",
    },
    {
        "id": "inhibit_recovery",
        "match": lambda ev: bool(_INHIBIT_RECOVERY_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1490", "mitre_tactic": "Impact", "mitre_technique": "Inhibit System Recovery",
        "severity": "CRITICAL", "risk_score": 90, "description": "Eliminación de copias de seguridad/shadow copies",
    },
    {
        "id": "disable_defenses",
        "match": lambda ev: bool(_DISABLE_DEFENSES_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1562.001", "mitre_tactic": "Defense Evasion", "mitre_technique": "Disable or Modify Tools",
        "severity": "HIGH", "risk_score": 70, "description": "Intento de deshabilitar Windows Defender/Firewall",
    },
    {
        "id": "account_manipulation",
        "match": lambda ev: bool(_ACCOUNT_MANIPULATION_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1136.001", "mitre_tactic": "Persistence", "mitre_technique": "Local Account",
        "severity": "HIGH", "risk_score": 60, "description": "Creación de cuenta local o escalado a administradores",
    },
    {
        "id": "tool_download",
        "match": lambda ev: bool(_DOWNLOAD_TOOL_RX.search(_process_cmdline(ev))),
        "mitre_id": "T1105", "mitre_tactic": "Command and Control", "mitre_technique": "Ingress Tool Transfer",
        "severity": "MEDIUM", "risk_score": 40, "description": "Descarga de herramienta externa vía línea de comandos",
    },
    {
        "id": "office_spawns_shell",
        "match": lambda ev: (ev.get('parent_name') or '').lower() in _OFFICE_PARENTS
                             and (ev.get('process_name') or '').split('\\')[-1].lower() in _SUSPICIOUS_CHILDREN,
        "mitre_id": "T1566", "mitre_tactic": "Initial Access", "mitre_technique": "Phishing",
        "severity": "CRITICAL", "risk_score": 85, "description": "Aplicación Office lanzó un intérprete de comandos (posible macro maliciosa)",
    },
]

REGISTRY_RULES = [
    {
        "id": "run_key_persistence",
        "match": lambda ev: True,  # el recolector ya filtra por rutas Run/RunOnce
        "mitre_id": "T1547.001", "mitre_tactic": "Persistence", "mitre_technique": "Registry Run Keys / Startup Folder",
        "severity": "HIGH", "risk_score": 65, "description": "Nueva entrada de persistencia en el registro (Run/RunOnce)",
    },
]

SERVICE_RULES = [
    {
        "id": "new_service",
        "match": lambda ev: True,  # el recolector ya filtra por creación de servicio
        "mitre_id": "T1543.003", "mitre_tactic": "Persistence", "mitre_technique": "Windows Service",
        "severity": "HIGH", "risk_score": 65, "description": "Nuevo Servicio de Windows creado",
    },
]

RULESETS_BY_CATEGORY = {
    "process": PROCESS_RULES,
    "registry": REGISTRY_RULES,
    "service": SERVICE_RULES,
}


def evaluate(category, event):
    """Evalúa un evento crudo contra todas las reglas de su categoría.
    Devuelve una lista de matches (puede ser vacía, uno, o varios) — cada
    match es un dict con mitre_id/tactic/technique/severity/risk_score/
    description/rule_id, listo para adjuntarse al evento antes de encolarlo.
    """
    rules = RULESETS_BY_CATEGORY.get(category, [])
    matches = []
    for rule in rules:
        try:
            if rule["match"](event):
                matches.append({
                    "rule_id": rule["id"],
                    "mitre_id": rule["mitre_id"],
                    "mitre_tactic": rule["mitre_tactic"],
                    "mitre_technique": rule["mitre_technique"],
                    "severity": rule["severity"],
                    "risk_score": rule["risk_score"],
                    "description": rule["description"],
                })
        except Exception:
            # Una regla mal formada no debe tumbar la evaluación de las demás
            # ni del evento — se descarta esa regla puntual en silencio.
            continue
    return matches
