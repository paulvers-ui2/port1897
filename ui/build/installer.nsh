; AuroraVPN Service (cmd/fswin/service_windows.go) starts the engine without
; a UAC prompt each time protection starts. The installer itself runs as
; admin (per-machine install), so it sets the service up once.

; AuroraVPN 0.2.28 to 0.2.30 was a Rust app on Tauri (desktop/, now in git
; history only); Tauri's installer keyed its Apps & Features entry by the
; product name
!define TAURI_UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuroraVPN"

; Removes the Tauri AuroraVPN before this one goes in, with its own
; uninstaller run quietly: it closes the app, removes its shortcuts, files
; and Apps & Features entry, and keeps the user's files in
; %APPDATA%\AuroraVPN (both apps use the same ones). Stops the install if
; it fails.
!macro customInit
  Push $R0
  Push $R1
  Push $R2
  ; $R2: its uninstaller, from "C:\...\AuroraVPN\uninstall.exe"
  ReadRegStr $R2 HKLM "${TAURI_UNINSTKEY}" "UninstallString"
  StrCpy $R0 $R2 1
  ${if} $R0 == '"'
    StrCpy $R2 $R2 -1 1
  ${endIf}
  ${ifNot} ${FileExists} "$R2"
    StrCpy $R2 "$PROGRAMFILES64\AuroraVPN\uninstall.exe"
  ${endIf}
  ; $R1: its folder, the path without "\uninstall.exe"
  StrCpy $R0 $R2 "" -14
  StrCpy $R1 $R2 -14

  ${if} $R0 == "\uninstall.exe"
  ${andIf} ${FileExists} "$R2"
  ${andIf} ${FileExists} "$R1\engine\fswin.exe"
    DetailPrint "Removing the previous AuroraVPN (Tauri) from $R1; your settings stay"
    ; its service runs engine\fswin.exe from that folder: stop it and its
    ; engine first, or the uninstaller would find them running
    nsExec::ExecToLog '"$R1\engine\fswin.exe" -service uninstall'
    Pop $R0
    ; run a copy from the temp folder: it can then remove its own file, and
    ; _?= makes ExecWait wait for it. Quiet, it keeps the app data (its
    ; "Delete the application data" box is not ticked).
    InitPluginsDir
    ClearErrors
    CopyFiles /SILENT "$R2" "$PLUGINSDIR\old-uninstaller.exe"
    ${ifNot} ${Errors}
      ExecWait '"$PLUGINSDIR\old-uninstaller.exe" /S _?=$R1' $R0
    ${endIf}
    ${if} ${Errors}
      StrCpy $R0 "not started"
    ${endIf}
    ${if} $R0 != 0
    ${orIf} ${FileExists} "$R1\AuroraVPN.exe"
      ; give it its service back and stop
      ${if} ${FileExists} "$R1\engine\fswin.exe"
        nsExec::ExecToLog '"$R1\engine\fswin.exe" -service install -app "$R1\AuroraVPN.exe"'
        Pop $R0
      ${endIf}
      MessageBox MB_OK|MB_ICONSTOP "The previous AuroraVPN could not be removed. Close it, or restart Windows, then run this installer again." /SD IDOK
      Abort
    ${endIf}
    ; left behind when it ran in place
    Delete "$R2"
    DeleteRegKey HKLM "${TAURI_UNINSTKEY}"
  ${endIf}
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
