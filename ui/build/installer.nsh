; AuroraVPN Service (cmd/fswin/service_windows.go) starts the engine without
; a UAC prompt each time protection starts, and keeps it running
; (keep_windows.go). The installer itself runs as admin (per-machine
; install), so it sets the service up once.

!include "FileFunc.nsh"

; AuroraVPN 0.2.10 to 0.2.6x was a Tauri app (Rust, desktop/, since
; removed), installed by its own NSIS installer under this key, often in the
; same folder as this app. It goes first: its uninstaller runs quietly, which
; keeps the user's settings (%APPDATA%\AuroraVPN, shared with this app).
!define TAURI_UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuroraVPN"

!macro customInit
  Push $R0
  Push $R1
  Push $R2
  SetRegView 64
  ReadRegStr $R2 HKLM "${TAURI_UNINSTKEY}" "UninstallString"
  ; "C:\Program Files\AuroraVPN\uninstall.exe" without its quotes
  StrCpy $R0 $R2 1
  ${if} $R0 == '"'
    StrCpy $R2 $R2 "" 1
    StrLen $R0 $R2
    IntOp $R0 $R0 - 1
    StrCpy $R2 $R2 $R0
  ${endIf}
  ${if} $R2 != ""
  ${andIf} ${FileExists} "$R2"
    ${GetParent} "$R2" $R1
    ; its service runs engine\fswin.exe from that folder: stop it and its
    ; engine first, or the uninstaller would find them running
    nsExec::ExecToLog '"$R1\engine\fswin.exe" -service uninstall'
    Pop $R0
    ; a copy in the temp folder can remove the original; _?= makes ExecWait
    ; wait for it (an NSIS uninstaller otherwise copies itself and returns)
    InitPluginsDir
    ClearErrors
    CopyFiles /SILENT "$R2" "$PLUGINSDIR\tauri-uninstall.exe"
    ${ifNot} ${Errors}
      ExecWait '"$PLUGINSDIR\tauri-uninstall.exe" /S _?=$R1' $R0
    ${endIf}
    ${if} ${Errors}
    ${orIf} $R0 != 0
      ; it did not finish: give it its service back and stop here
      nsExec::ExecToLog '"$R1\engine\fswin.exe" -service install -app "$R1\AuroraVPN.exe"'
      Pop $R1
      MessageBox MB_OK|MB_ICONSTOP "The previous AuroraVPN could not be removed (error $R0). Restart Windows, then run this installer again." /SD IDOK
      Quit
    ${endIf}
    ; left behind when it ran from the temp folder
    Delete "$R2"
    RMDir /r "$R1\engine"
    DeleteRegKey HKLM "${TAURI_UNINSTKEY}"
  ${endIf}
  SetRegView lastused
  Pop $R2
  Pop $R1
  Pop $R0
!macroend

!macro customInstall
  DetailPrint "Setting up AuroraVPN Service"
  Push $0
  nsExec::ExecToLog '"$INSTDIR\resources\engine\fswin.exe" -service install -app "$INSTDIR\${APP_EXECUTABLE_FILENAME}"'
  Pop $0
  ${if} $0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "AuroraVPN Service could not be set up (error $0). AuroraVPN still works, but asks for admin permission each time protection starts." /SD IDOK
  ${endIf}
  Pop $0
!macroend

!macro customUnInstall
  ; stops the engine the service started, then removes the service; an
  ; update installs it again
  Push $0
  nsExec::ExecToLog '"$INSTDIR\resources\engine\fswin.exe" -service uninstall'
  Pop $0
  Pop $0
!macroend
