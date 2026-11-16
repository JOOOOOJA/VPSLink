#ifndef ReleaseVersion
  #define ReleaseVersion "0.3.0"
#endif
#define ProjectRoot SourcePath + "..\..\"
[Setup]
SetupArchitecture=x64
AppId={{3D0F8692-329B-4708-873B-1A6C40D77ED2}
AppName=VPSLink
AppVersion={#ReleaseVersion}
AppPublisher=VPSLink contributors
SetupIconFile={#ProjectRoot}assets\VPSLink.ico
DefaultDirName={autopf}\VPSLink
DefaultGroupName=VPSLink
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19044
PrivilegesRequired=admin
OutputDir={#ProjectRoot}artifacts
OutputBaseFilename=VPSLink-{#ReleaseVersion}-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=110
UninstallDisplayIcon={app}\VPSLink.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
InfoBeforeFile=Install-info.txt
Uninstallable=yes
[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; Flags: unchecked
[Files]
Source: "{#ProjectRoot}artifacts\installer-stage\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectRoot}artifacts\dependencies\windowsdesktop-runtime-10.0.15-win-x64.exe"; Flags: dontcopy
Source: "Remove-Autostart.ps1"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\VPSLink"; Filename: "{app}\VPSLink.exe"
Name: "{group}\Инструкция"; Filename: "{app}\Help\thingsnotfun-link-guide.html"
Name: "{autodesktop}\VPSLink"; Filename: "{app}\VPSLink.exe"; Tasks: desktopicon
[Run]
Filename: "{app}\Help\thingsnotfun-link-guide.html"; Description: "Открыть инструкцию"; Flags: postinstall shellexec skipifsilent unchecked
[InstallDelete]
Type: files; Name: "{app}\ThingsNotFun-Link.exe"
Type: files; Name: "{app}\ThingsNotFun-Link.dll"
Type: files; Name: "{app}\ThingsNotFun-Link.deps.json"
Type: files; Name: "{app}\ThingsNotFun-Link.runtimeconfig.json"
Type: files; Name: "{commonprograms}\ThingsNotFun Link\ThingsNotFun Link.lnk"
Type: files; Name: "{commonprograms}\ThingsNotFun Link\Инструкция.lnk"
Type: files; Name: "{commondesktop}\ThingsNotFun Link.lnk"
[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\Remove-Autostart.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveMatchingLinkAutostart"
[Code]
function HasDesktopRuntime: Boolean;
var Names: TArrayOfString; I: Integer; Found: TFindRec; Base: String;
begin
  Result := False;
  if RegGetValueNames(HKLM64, 'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App', Names) then
    for I := 0 to GetArrayLength(Names) - 1 do
      if (StrToIntDef(Copy(Names[I], 1, Pos('.', Names[I]) - 1), 0) >= 6) then Result := True;
  Base := ExpandConstant('{commonpf64}\dotnet\shared\Microsoft.WindowsDesktop.App\');
  if not Result and FindFirst(Base + '*', Found) then begin
    try
      repeat
        if (StrToIntDef(Copy(Found.Name, 1, Pos('.', Found.Name) - 1), 0) >= 6) and FileExists(Base + Found.Name + '\System.Windows.Forms.dll') then Result := True;
      until not FindNext(Found);
    finally FindClose(Found); end;
  end;
  if Result then Log('Compatible x64 Desktop Runtime found.');
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  Result := '';
  if not HasDesktopRuntime then begin
    ExtractTemporaryFile('windowsdesktop-runtime-10.0.15-win-x64.exe');
    if not Exec(ExpandConstant('{tmp}\windowsdesktop-runtime-10.0.15-win-x64.exe'), '/install /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, Code) then begin
      Result := 'Не удалось запустить установку .NET Desktop Runtime.'; exit;
    end;
    if Code = 3010 then NeedsRestart := True
    else if Code <> 0 then begin Result := 'Не удалось установить .NET Desktop Runtime. Код: ' + IntToStr(Code); exit; end;
  end;
end;
