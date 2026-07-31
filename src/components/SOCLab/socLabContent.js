export const labData = {
  overview: {
    title: "SOC Bajo Ataque",
    subtitle: "ESET PROTECT Elite + ESET Inspect",
    description: "Ejercicio guiado de detección e investigación de incidentes, basado en tres escenarios encadenados: acceso inicial, movimiento lateral y doble extorsión.",
    duration: "3,5 – 4 horas",
    target: "CIO, CISO, líderes de TI y SOC",
    agenda: [
      "Contexto: ¿por qué un SOC bajo ataque?",
      "Vista general de la historia en 3 escenarios.",
      "Escenario 1: Reconocimiento + Persistencia.",
      "Escenario 2: Credenciales robadas + Movimiento lateral.",
      "Escenario 3: Exfiltración de datos + Ransomware.",
      "Qué demostró ESET PROTECT Elite / ESET Inspect para el negocio.",
      "Lecciones clave y siguientes pasos recomendados."
    ],
    scenarios: [
      {
        id: 1,
        title: "Reconocimiento + Persistencia",
        items: [
          "Port scan interno y reconocimiento del host.",
          "PowerShell ofuscado con -EncodedCommand.",
          "Uso de certutil.exe como LOLBAS.",
          "Persistencia vía Run Key y Scheduled Task."
        ]
      },
      {
        id: 2,
        title: "Credenciales + Lateral",
        items: [
          "Robo de credenciales (LSASS, SAM, VSS).",
          "Reconocimiento de dominio, grupos privilegiados.",
          "Intentos de movimiento lateral por SMB, WMI y WinRM."
        ]
      },
      {
        id: 3,
        title: "Exfiltración + Ransomware",
        items: [
          "Staging y compresión de datos sensibles.",
          "Exfiltración HTTP y DNS.",
          "Eliminación de shadow copies y cifrado simulado."
        ]
      }
    ]
  },
  scenarios: [
    {
      id: 1,
      title: "Escenario 1: Reconocimiento + Persistencia",
      tagline: "El atacante obtiene acceso inicial",
      tags: ["Port Scan T1046", "PS -EncodedCommand T1027", "certutil LOLBAS T1140", "Run Key T1547.001", "Sched Task T1053.005"],
      context: "Un usuario abre un archivo adjunto de phishing. El atacante ejecuta un script PowerShell ofuscado, mapea la red, identifica los controles de seguridad instalados y establece mecanismos de persistencia.",
      killChain: [
        { name: "Recon Host", tech: "T1082" },
        { name: "Security Discovery", tech: "T1518.001" },
        { name: "Port Scan", tech: "T1046" },
        { name: "PS Ofuscado", tech: "T1027" },
        { name: "certutil LOLBAS", tech: "T1140" },
        { name: "Persistencia", tech: "T1547.001" }
      ],
      detections: [
        { tech: "T1059.001", behavior: "powershell.exe con -EncodedCommand Base64", severity: "THREAT", score: "70-100", location: "Detections > Rule 1.1" },
        { tech: "T1140", behavior: "certutil.exe -encode y -decode en %TEMP%", severity: "THREAT", score: "70-100", location: "Detections > certutil.exe" },
        { tech: "T1547.001", behavior: "Escritura en HKCU...Run\\WinSyncAgent", severity: "WARNING", score: "40-69", location: "Registry events" },
        { tech: "T1053.005", behavior: "New-ScheduledTask desde PowerShell", severity: "WARNING", score: "40-69", location: "Detections > Sched Task" }
      ],
      phases: [
        {
          num: 1,
          name: "Detección inicial",
          desc: "Localizar la detección THREAT principal de PowerShell ofuscado.",
          steps: [
            "Detections > Filtrar Severity: Threat > identificar 'PowerShell encoded command'",
            "Tab Process Tree: ¿cuál es el proceso padre de powershell.exe?",
            "Confirmar MITRE Technique y Rule disparada"
          ]
        },
        {
          num: 2,
          name: "Persistencia",
          desc: "Identificar los mecanismos de persistencia en el registro y tareas programadas.",
          steps: [
            "Detections > buscar 'Registry AutoStart' o 'Run Key'",
            "Events > Registry events: ¿qué clave HKCU fue modificada?",
            "Anotar nombre Run Key (WinSyncAgent) y tarea (WindowsTelemetrySync)"
          ]
        }
      ],
      artifacts: [
        { icon: "🔑", title: "Run Key", value: "HKCU\\...\\Run\\WinSyncAgent" },
        { icon: "⏰", title: "Tarea Programada", value: "WindowsTelemetrySync" },
        { icon: "🛠️", title: "LOLBAS", value: "%TEMP%\\patch_installer.exe" }
      ],
      questions: [
        { q: "¿Cuál fue el primer proceso sospechoso detectado y a qué hora?", hint: "Detections > ordenar por fecha más antigua." },
        { q: "¿Qué comando real oculta el Base64 de la Run Key?", hint: "Registry events > decodificar Base64." }
      ]
    },
    {
      id: 2,
      title: "Escenario 2: Credenciales + Lateral",
      tagline: "Robando credenciales y moviéndose por la red",
      tags: ["LSASS dump T1003.001", "SAM/SYSTEM T1003.002", "Domain Recon T1482", "SMB/WMI/WinRM"],
      context: "El atacante utiliza el endpoint comprometido para robar credenciales, identificar cuentas privilegiadas y moverse lateralmente hacia otros equipos.",
      killChain: [
        { name: "Credential Dumping", tech: "T1003" },
        { name: "Domain Recon", tech: "T1482" },
        { name: "Lateral Movement", tech: "T1021" },
        { name: "Tampering AV", tech: "T1562.001" }
      ],
      detections: [
        { tech: "T1003.001", behavior: "Volcado de lsass.exe en %TEMP%", severity: "THREAT", score: "80-100", location: "Detections > LSASS access" },
        { tech: "T1003.002", behavior: "reg.exe save HKLM\\SAM", severity: "THREAT", score: "80-100", location: "Registry dump" },
        { tech: "T1562.001", behavior: "Set-MpPreference -DisableRealtimeMonitoring", severity: "THREAT", score: "90-100", location: "PowerShell tampering" },
        { tech: "T1047", behavior: "wmic /node: process call create", severity: "WARNING", score: "50-70", location: "Lateral Movement" }
      ],
      phases: [
        {
          num: 1,
          name: "Robo de Credenciales",
          desc: "Investigar el acceso a LSASS y el dump del registro SAM.",
          steps: [
            "Detections > filtrar por Threat > buscar LSASS access",
            "File events: localizar lsass_esetlab.dmp y sam_esetlab.hiv",
            "Anotar rutas y tiempos de creación"
          ]
        },
        {
          num: 2,
          name: "Movimiento Lateral",
          desc: "Identificar conexiones SMB, WMI y WinRM hacia otros hosts.",
          steps: [
            "Computer detail > Network > filtrar puertos 445, 135, 5985",
            "Correlacionar con procesos net.exe y wmic.exe",
            "Identificar IPs de LateralTargets"
          ]
        }
      ],
      artifacts: [
        { icon: "🔓", title: "LSASS Dump", value: "%TEMP%\\ESETLab_E2\\lsass_esetlab.dmp" },
        { icon: "🗄️", title: "SAM/SYSTEM", value: "sam_esetlab.hiv / system_esetlab.hiv" },
        { icon: "📡", title: "Movimiento Lateral", value: "SMB/WMI/WinRM connections" }
      ],
      questions: [
        { q: "¿Qué técnica de credential dumping es más peligrosa y por qué?", hint: "Compara el contenido de LSASS vs SAM/SYSTEM." },
        { q: "¿Qué hosts fueron objetivo de movimiento lateral?", hint: "Cruza Network events con procesos net.exe/wmic.exe." }
      ]
    },
    {
      id: 3,
      title: "Escenario 3: Exfiltración + Ransomware",
      tagline: "Double extortion en entorno controlado",
      tags: ["Data Staging T1074", "Exfil HTTP/DNS", "vssadmin delete T1490", ".ESET_LOCKED"],
      context: "Fase final: recolección de datos, exfiltración a servidor externo y cifrado de archivos eliminando shadow copies.",
      killChain: [
        { name: "Data Staging", tech: "T1074" },
        { name: "Exfiltración", tech: "T1041" },
        { name: "Inhibit Recovery", tech: "T1490" },
        { name: "Ransomware", tech: "T1486" }
      ],
      detections: [
        { tech: "T1490", behavior: "vssadmin delete shadows /all /quiet", severity: "THREAT", score: "100", location: "Detections > Inhibit Recovery" },
        { tech: "T1486", behavior: "Renombrado masivo a .ESET_LOCKED", severity: "THREAT", score: "100", location: "Anti-Ransomware Alerta" },
        { tech: "T1041", behavior: "Invoke-WebRequest HTTP POST Base64", severity: "WARNING", score: "60-80", location: "Network events > 185.220.101.50" },
        { tech: "T1048.003", behavior: "DNS Tunneling a update-cdn-ms.net", severity: "WARNING", score: "60-80", location: "DNS telemetry" }
      ],
      phases: [
        {
          num: 1,
          name: "Exfiltración",
          desc: "Detectar el envío de datos vía HTTP y DNS.",
          steps: [
            "Network > filtrar por IP 185.220.101.50",
            "DNS telemetry: buscar queries a update-cdn-ms.net",
            "Verificar si la exfiltración fue exitosa o bloqueada"
          ]
        },
        {
          num: 2,
          name: "Ransomware",
          desc: "Investigar el borrado de shadows y el cifrado de archivos.",
          steps: [
            "Detections > buscar vssadmin delete shadows",
            "File events: buscar archivos .ESET_LOCKED",
            "Localizar HOW_TO_RECOVER_FILES.html en Desktop"
          ]
        }
      ],
      artifacts: [
        { icon: "📦", title: "Staging Zip", value: "backup_financiero.zip" },
        { icon: "☣️", title: "Ransom Extension", value: ".ESET_LOCKED" },
        { icon: "📝", title: "Ransom Note", value: "HOW_TO_RECOVER_FILES.html" }
      ],
      questions: [
        { q: "¿Cuántos archivos fueron afectados por el cifrado?", hint: "Cuenta los eventos de renombrado a .ESET_LOCKED." },
        { q: "¿Por qué se conoce como 'double extortion'?", hint: "Impacto de exfiltración + cifrado." }
      ]
    }
  ]
};
