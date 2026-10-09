; AuroraVPN Service (cmd/fswin/service_windows.go) starts the engine without
; a UAC prompt each time protection starts. The installer itself runs as
; admin (per-machine install), so it sets the service up once.

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
