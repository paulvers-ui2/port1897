; Copyright (c) 2026 RethinkDNS and its authors.
;
; This Source Code Form is subject to the terms of the Mozilla Public
; License, v. 2.0. If a copy of the MPL was not distributed with this
; file, You can obtain one at http://mozilla.org/MPL/2.0/.

; Hooks into Tauri's NSIS installer (tauri-bundler's installer.nsi, which
; runs as admin: installMode perMachine). The installed app:
;   $INSTDIR\AuroraVPN.exe
;   $INSTDIR\engine\fswin.exe, usque.exe, wintun.dll and their licenses
; AuroraVPN Service (cmd/fswin/service_windows.go) starts the engine without
; a UAC prompt each time protection starts; the installer sets it up once.
; The user's files stay in %APPDATA%\AuroraVPN through updates; uninstalling
; deletes them only when "Delete the application data" is ticked.

; AuroraVPN 0.2 was an Electron app; electron-builder keyed its registry
; entries by a GUID made from its appId, io.github.port1897
!define ELECTRON_GUID "b08e5cfd-4d07-54eb-9603-c0c30dd5023b"
!define ELECTRON_UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ELECTRON_GUID}"
!define ELECTRON_INSTKEY "Software\${ELECTRON_GUID}"

!macro NSIS_HOOK_PREINSTALL
  ; the app first: it would see its engine stop below
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  ; an update over this app: the service runs engine\fswin.exe, about to be
  ; replaced; POSTINSTALL sets it up again
  ${If} ${FileExists} "$INSTDIR\engine\fswin.exe"
    nsExec::ExecToLog '"$INSTDIR\engine\fswin.exe" -service uninstall'
    Pop $0
  ${EndIf}

  !insertmacro AuroraRemoveElectronApp
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Setting up AuroraVPN Service"
  Push $0
  nsExec::ExecToLog '"$INSTDIR\engine\fswin.exe" -service install -app "$INSTDIR\${MAINBINARYNAME}.exe"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "AuroraVPN Service could not be set up (error $0). AuroraVPN still works, but asks for admin permission each time protection starts." /SD IDOK
  ${EndIf}
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  ; stops the engine the service started, then removes the service; an
  ; update sets it up again
  Push $0
  nsExec::ExecToLog '"$INSTDIR\engine\fswin.exe" -service uninstall'
  Pop $0
  Pop $0
  ; the service's log, so the folders can go
  Delete "$INSTDIR\service.log"
  Delete "$INSTDIR\service.log.old"
  Delete "$INSTDIR\engine\service.log"
  Delete "$INSTDIR\engine\service.log.old"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    ; the Electron app's start-at-login entries (the app replaces them when
    ; it runs; Tauri's uninstaller removes the new one)
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "electron.app.AuroraVPN"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "electron.app.port1897"
  ${EndIf}
  ; "Delete the application data" ticked: Tauri removed %APPDATA%\AuroraVPN
  ; and %LOCALAPPDATA%\AuroraVPN of the user running the uninstaller; this
  ; is the folder of the app's old name, port1897
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    RMDir /r "$APPDATA\port1897"
    SetShellVarContext all
  ${EndIf}
!macroend

; Removes AuroraVPN 0.2 (Electron), found by its uninstall entry or in
; $INSTDIR, with its own uninstaller run quietly: it closes the old app,
; removes its shortcuts, files and Apps & Features entry, and keeps the
; user's files (no --delete-app-data). Stops the install if it fails.
!macro AuroraRemoveElectronApp
  Push $R0
  Push $R1
  Push $R2
  ; $R2: the old uninstaller, from "C:\...\Uninstall AuroraVPN.exe" /allusers
  ReadRegStr $R2 HKLM "${ELECTRON_UNINSTKEY}" "UninstallString"
  StrCpy $R0 $R2 1
  ${If} $R0 == '"'
    StrCpy $R2 $R2 "" 1
    ${StrLoc} $R0 $R2 '"' ">"
    StrCpy $R2 $R2 $R0
  ${EndIf}
  ${If} $R2 == ""
  ${OrIfNot} ${FileExists} "$R2"
    StrCpy $R2 "$INSTDIR\Uninstall ${PRODUCTNAME}.exe"
  ${EndIf}

  ${If} ${FileExists} "$R2"
    ; $R1: its folder
    ${GetParent} "$R2" $R1
    DetailPrint "Removing the previous AuroraVPN (Electron) from $R1; your settings stay"
    ; its service runs fswin.exe from that folder: stop it and its engine
    ; first, or the uninstaller would find them running (and Windows would
    ; restart the service)
    nsExec::ExecToLog '"$R1\resources\engine\fswin.exe" -service uninstall'
    Pop $R0
    ; run a copy from the temp folder, as electron-builder's own updates do:
    ; it can then remove its own file, and _?= makes ExecWait wait for it
    ; (an NSIS uninstaller otherwise copies itself to %TEMP% and returns)
    InitPluginsDir
    ClearErrors
    CopyFiles /SILENT "$R2" "$PLUGINSDIR\old-uninstaller.exe"
    ${IfNot} ${Errors}
      ExecWait '"$PLUGINSDIR\old-uninstaller.exe" /S /allusers --updated _?=$R1' $R0
    ${EndIf}
    ${If} ${Errors}
      ClearErrors
      ExecWait '"$R2" /S /allusers --updated _?=$R1' $R0
      ${IfThen} ${Errors} ${|} StrCpy $R0 "not started" ${|}
    ${EndIf}
    ; --updated: it removes everything or nothing (a file in use), so a
    ; failure leaves the old app whole; give it its service back and stop
    ${If} $R0 != 0
    ${OrIf} ${FileExists} "$R1\resources\app.asar"
      nsExec::ExecToLog '"$R1\resources\engine\fswin.exe" -service install -app "$R1\${MAINBINARYNAME}.exe"'
      Pop $0
      MessageBox MB_OK|MB_ICONSTOP "The previous AuroraVPN could not be removed (error $R0). Restart Windows, then run this installer again." /SD IDOK
      Abort "The previous AuroraVPN could not be removed (error $R0)."
    ${EndIf}
    ; left behind if it ran in place
    Delete "$R2"
    ${If} $R1 != $INSTDIR
      RMDir "$R1"
    ${EndIf}
  ${EndIf}
  ; its Apps & Features entry, also when its uninstaller is gone
  DeleteRegKey HKLM "${ELECTRON_UNINSTKEY}"
  DeleteRegKey HKLM "${ELECTRON_INSTKEY}"
  ; the uninstaller may have removed $INSTDIR when it was the same folder
  SetOutPath $INSTDIR
  Pop $R2
  Pop $R1
  Pop $R0
!macroend
