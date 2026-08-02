; Instalador del Sensor EDR de CyberIntel EC.
; Compilar con: iscc sensor.iss
; Requiere que agent\dist\sensor.exe ya exista (generado con PyInstaller —
; ver agent\build_exe.ps1). Este script NO compila el .exe, solo lo empaqueta.

#define MyAppName "CyberIntel EC Sensor"
#define MyAppVersion "1.0"
#define MyAppPublisher "CyberIntel EC"
#define MyServiceName "CyberIntelEDRSensor"

[Setup]
AppId={{B7E1B2B4-6C1B-4B1E-9C1B-CYBERINTELEDR}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\CyberIntel EC\Sensor
DefaultGroupName=CyberIntel EC
DisableProgramGroupPage=yes
; Requiere privilegios de administrador: instalar un Servicio de Windows no
; es posible con permisos de usuario estándar.
PrivilegesRequired=admin
OutputDir=output
OutputBaseFilename=CyberIntelSensorSetup
Compression=lzma
SolidCompression=yes
UninstallDisplayIcon={app}\sensor.exe
; Aparece en "Programas y características" con nombre y versión reales,
; y con un desinstalador que Windows sabe invocar.
UninstallDisplayName={#MyAppName}

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\dist\sensor.exe"; DestDir: "{app}"; Flags: ignoreversion

[Code]
var
  ServerPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  { Pantalla propia del wizard para pedir server_url y agent_token — el
    instalador queda autocontenido, no requiere que el analista edite ningún
    archivo a mano después de instalar. }
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Configuración del servidor', 'Datos de conexión de CyberIntel EC',
    'Estos valores los provee el dashboard de CyberIntel EC (vista Endpoints → Descargar Sensor). ' +
    'El sensor no podrá conectarse sin ellos.');
  ServerPage.Add('URL del servidor (ej. https://tu-app.vercel.app):', False);
  ServerPage.Add('Token del agente:', False);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    if (Trim(ServerPage.Values[0]) = '') or (Trim(ServerPage.Values[1]) = '') then
    begin
      MsgBox('Completa la URL del servidor y el token del agente para continuar.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure WriteAgentConfig();
var
  ConfigPath: String;
  ConfigContent: String;
begin
  ConfigPath := ExpandConstant('{app}\agent.config.json');
  ConfigContent :=
    '{' + #13#10 +
    '  "server_url": "' + ServerPage.Values[0] + '",' + #13#10 +
    '  "agent_token": "' + ServerPage.Values[1] + '",' + #13#10 +
    '  "ca_cert": null,' + #13#10 +
    '  "verify_tls": true,' + #13#10 +
    '  "poll_interval_seconds": 30' + #13#10 +
    '}';
  SaveStringToFile(ConfigPath, ConfigContent, False);
end;

[Run]
; El propio sensor.exe sabe registrarse como servicio (win32serviceutil,
; ver agent/sensor.py) — el instalador solo invoca esos comandos, no
; duplica la lógica de "sc create" a mano.
; --startup=auto es obligatorio: sin él, pywin32 registra el servicio en
; Manual (DEMAND_START) y no arrancaría solo tras un reinicio, que es
; justamente el punto de instalarlo como servicio en vez de un script suelto.
Filename: "{app}\sensor.exe"; Parameters: "--startup auto install"; StatusMsg: "Registrando el servicio..."; Flags: runhidden waituntilterminated; BeforeInstall: WriteAgentConfig
Filename: "{app}\sensor.exe"; Parameters: "start"; StatusMsg: "Iniciando el sensor..."; Flags: runhidden waituntilterminated

[UninstallRun]
; RunOnceId evita que Inno lo repita si el uninstall se reintenta.
Filename: "{app}\sensor.exe"; Parameters: "stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopSensorService"
Filename: "{app}\sensor.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSensorService"

[UninstallDelete]
Type: files; Name: "{app}\agent.config.json"
Type: files; Name: "{app}\agent_id.txt"
; server.cert no lo instala este paquete (ca_cert: null usa la CA pública del
; sistema en producción), pero si un analista copió uno a mano para pruebas
; locales, la desinstalación debe dejar la carpeta limpia igual.
Type: files; Name: "{app}\server.cert"
Type: dirifempty; Name: "{app}"
