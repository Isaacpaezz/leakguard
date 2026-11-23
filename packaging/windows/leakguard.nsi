; The leakguard installer for Windows: scripts/build-windows.sh builds it
; with makensis, once per architecture. It installs per machine into
; %ProgramFiles%\leakguard (the CLI leakguard.exe, the tray leakguard-tray.exe
; and the guide), adds a Start menu shortcut and the Settings > Apps entry.
; It never installs the background service: the tray's setup does, with
; leakguard.exe enable. On an upgrade with the service installed it runs
; leakguard.exe reinstall-service, so the service runs the new copy with
; the saved choice. The uninstaller runs leakguard.exe disable first.
;
; The folder is always %ProgramFiles%\leakguard, which only administrators
; may write: the tray and the uninstaller run its leakguard.exe elevated,
; so a folder a standard user can write (picked with /D=) would let that
; user swap the binary. The installer has no directory page and refuses a
; /D= that names another folder; the uninstaller refuses to run from one.
;
; Exit codes: 0 done. The installer exits with 2 when /D= names another
; folder (nothing installed) and with 3 when it installed the files but
; could not update the background service. The uninstaller exits with 2
; when disable failed or it runs from another folder: it then removes no
; file (the CLI, the uninstaller and the Settings entry stay, so the user
; can retry). A plain uninstall.exe returns before its copy in %TEMP%
; finishes; run it as uninstall.exe /S _?=DIR (last, unquoted) to wait
; for its exit code.
;
; Defines (makensis -D): VERSION (0.2.0 or 0.2.0-beta.1), VIVERSION (its
; numeric form, 0.2.0.0), ARCH (amd64 or arm64), BINDIR (leakguard.exe and
; leakguard-tray.exe), LICENSEFILE, OUTFILE, and GUIDE (optional:
; docs/install-windows.md).

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma

!macro Require NAME
  !ifndef ${NAME}
    !error "Define ${NAME} (see scripts/build-windows.sh)"
  !endif
!macroend
!insertmacro Require VERSION
!insertmacro Require VIVERSION
!insertmacro Require ARCH
!insertmacro Require BINDIR
!insertmacro Require LICENSEFILE
!insertmacro Require OUTFILE
!if "${ARCH}" != "amd64"
  !if "${ARCH}" != "arm64"
    !error "ARCH must be amd64 or arm64"
  !endif
!endif

!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh
!include FileFunc.nsh

!define APPNAME "leakguard"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\leakguard"
!define SERVICEKEY "SYSTEM\CurrentControlSet\Services\leakguard"
!define RUNKEY "Software\Microsoft\Windows\CurrentVersion\Run"

Name "${APPNAME}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\leakguard"
RequestExecutionLevel admin
BrandingText "${APPNAME} ${VERSION}"
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
; Open the tray as the signed-in user, never elevated like this installer.
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "$(OpenLeakguard)"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchTray
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; English first: Windows in another language than these two gets English.
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Spanish"

LangString OpenLeakguard ${LANG_ENGLISH} "Open leakguard"
LangString OpenLeakguard ${LANG_SPANISH} "Abrir leakguard"
LangString Needs64Bit ${LANG_ENGLISH} "leakguard needs 64-bit Windows."
LangString Needs64Bit ${LANG_SPANISH} "leakguard necesita Windows de 64 bits."
LangString NeedsARM64 ${LANG_ENGLISH} "This installer is for Windows on ARM. Download the installer that ends in windows-amd64-setup.exe."
LangString NeedsARM64 ${LANG_SPANISH} "Este instalador es para Windows en ARM. Descarga el instalador que termina en windows-amd64-setup.exe."
LangString ClosingTray ${LANG_ENGLISH} "Closing the leakguard icon so it can be updated"
LangString ClosingTray ${LANG_SPANISH} "Cerrando el icono de leakguard para poder actualizarlo"
LangString UpdatingService ${LANG_ENGLISH} "Updating the leakguard background service (your choice of services is kept)"
LangString UpdatingService ${LANG_SPANISH} "Actualizando el servicio de leakguard (se conservan los servicios que elegiste)"
LangString WrongFolder ${LANG_ENGLISH} "leakguard can only be installed in $\"$PROGRAMFILES64\leakguard$\", not in $\"$INSTDIR$\": only administrators may change the files in that folder, and leakguard runs them as administrator. Run the installer without /D=."
LangString WrongFolder ${LANG_SPANISH} "leakguard solo se puede instalar en $\"$PROGRAMFILES64\leakguard$\", no en $\"$INSTDIR$\": solo los administradores pueden cambiar los archivos de esa carpeta, y leakguard los ejecuta como administrador. Ejecuta el instalador sin /D=."
LangString WrongUninstallFolder ${LANG_ENGLISH} "This uninstaller is not in $\"$PROGRAMFILES64\leakguard$\", so it removes nothing. Uninstall leakguard from Settings > Apps."
LangString WrongUninstallFolder ${LANG_SPANISH} "Este desinstalador no está en $\"$PROGRAMFILES64\leakguard$\", así que no quita nada. Desinstala leakguard desde Configuración > Aplicaciones."
LangString ServiceNotUpdated ${LANG_ENGLISH} "leakguard was installed, but its background service could not be updated (code $0). The service is still running, so it keeps protecting you, but it may not run the new version.$\r$\n$\r$\nTo update it, open a terminal as administrator and run:$\r$\n$\"$INSTDIR\leakguard.exe$\" reinstall-service"
LangString ServiceNotUpdated ${LANG_SPANISH} "leakguard se instaló, pero su servicio en segundo plano no se pudo actualizar (código $0). El servicio sigue en marcha, así que te sigue protegiendo, pero puede que no use la versión nueva.$\r$\n$\r$\nPara actualizarlo, abre una terminal como administrador y ejecuta:$\r$\n$\"$INSTDIR\leakguard.exe$\" reinstall-service"
LangString ServiceNotRunning ${LANG_ENGLISH} "leakguard was installed, but its background service could not be updated (code $0) and is not running. Its firewall filters stay, but nothing keeps them up to date, so the protected services may stop working, even through your VPN.$\r$\n$\r$\nTo fix it, open a terminal as administrator and run:$\r$\n$\"$INSTDIR\leakguard.exe$\" enable"
LangString ServiceNotRunning ${LANG_SPANISH} "leakguard se instaló, pero su servicio en segundo plano no se pudo actualizar (código $0) y no está en marcha. Sus filtros del firewall siguen, pero nada los mantiene al día, así que los servicios protegidos pueden dejar de funcionar, incluso por tu VPN.$\r$\n$\r$\nPara arreglarlo, abre una terminal como administrador y ejecuta:$\r$\n$\"$INSTDIR\leakguard.exe$\" enable"
LangString RemovingService ${LANG_ENGLISH} "Removing the leakguard background service and its firewall filters"
LangString RemovingService ${LANG_SPANISH} "Quitando el servicio de leakguard y sus filtros del firewall"
LangString ServiceNotRemoved ${LANG_ENGLISH} "leakguard could not remove its protection completely (code $0), so the protected services may stay blocked. The program stays so you can retry.$\r$\n$\r$\nTo retry, uninstall leakguard again from Settings > Apps, or open a terminal as administrator and run:$\r$\n$\"$INSTDIR\leakguard.exe$\" disable"
LangString ServiceNotRemoved ${LANG_SPANISH} "leakguard no pudo quitar su protección por completo (código $0), así que los servicios protegidos pueden seguir bloqueados. El programa se queda para que puedas reintentarlo.$\r$\n$\r$\nPara reintentarlo, desinstala leakguard otra vez desde Configuración > Aplicaciones, o abre una terminal como administrador y ejecuta:$\r$\n$\"$INSTDIR\leakguard.exe$\" disable"

VIProductVersion "${VIVERSION}"
VIFileVersion "${VIVERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${APPNAME} ${VERSION} setup (${ARCH})"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "MIT License"

; A 64-bit build needs 64-bit Windows; the arm64 build needs Windows on
; ARM (Windows on ARM runs the amd64 build too).
!macro CheckArch
  !if "${ARCH}" == "arm64"
    ${IfNot} ${IsNativeARM64}
      MessageBox MB_OK|MB_ICONSTOP "$(NeedsARM64)" /SD IDOK
      Abort
    ${EndIf}
  !else
    ${IfNot} ${RunningX64}
      MessageBox MB_OK|MB_ICONSTOP "$(Needs64Bit)" /SD IDOK
      Abort
    ${EndIf}
  !endif
!macroend

; Accepts $INSTDIR only when it is $PROGRAMFILES64\leakguard (ignoring
; case and a trailing backslash) and then sets it to exactly that;
; otherwise shows MESSAGE and quits with exit code 2 (Abort in .onInit
; quits before anything runs). Uses $0.
!macro RequireDefaultFolder MESSAGE
  StrCpy $0 $INSTDIR 1 -1
  ${If} $0 == "\"
    StrCpy $INSTDIR $INSTDIR -1
  ${EndIf}
  ; LogicLib's == ignores case, like Windows paths.
  ${If} $INSTDIR != "$PROGRAMFILES64\leakguard"
    MessageBox MB_OK|MB_ICONSTOP "${MESSAGE}" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
  StrCpy $INSTDIR "$PROGRAMFILES64\leakguard"
!macroend

Function .onInit
  !insertmacro CheckArch
  SetShellVarContext all
  SetRegView 64
  ; /D= sets $INSTDIR before this runs; there is no directory page.
  !insertmacro RequireDefaultFolder "$(WrongFolder)"
FunctionEnd

Function un.onInit
  !insertmacro CheckArch
  SetShellVarContext all
  SetRegView 64
  ; $INSTDIR is the uninstaller's folder (or _?=): a copy elsewhere would
  ; elevate the leakguard.exe next to it.
  !insertmacro RequireDefaultFolder "$(WrongUninstallFolder)"
FunctionEnd

; explorer.exe opens the tray in the signed-in user's session, not elevated.
Function LaunchTray
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\leakguard-tray.exe"'
FunctionEnd

; Leaves the leakguard service's current state in $1 (SERVICE_START_PENDING
; is 2, SERVICE_RUNNING is 4), or 0 when the service is missing or cannot
; be queried. Uses $2-$5.
Function ServiceState
  StrCpy $1 0
  ; SC_MANAGER_CONNECT, then SERVICE_QUERY_STATUS.
  System::Call 'advapi32::OpenSCManagerW(p 0, p 0, i 1) p.r2'
  ${If} $2 != 0
    System::Call 'advapi32::OpenServiceW(p r2, w "leakguard", i 4) p.r3'
    ${If} $3 != 0
      ; SERVICE_STATUS: seven DWORDs, dwCurrentState is the second.
      System::Alloc 28
      Pop $4
      System::Call 'advapi32::QueryServiceStatus(p r3, p r4) i.r5'
      ${If} $5 != 0
        System::Call '*$4(i, i .r1)'
      ${EndIf}
      System::Free $4
      System::Call 'advapi32::CloseServiceHandle(p r3)'
    ${EndIf}
    System::Call 'advapi32::CloseServiceHandle(p r2)'
  ${EndIf}
FunctionEnd

; The running tray holds its file: close it before the files are replaced
; or removed. Nothing to do when it is not running. It closes every
; user's tray, not only this session's (taskkill /FI "SESSION eq N"
; would be simple): another signed-in user's tray would keep its file
; locked, so an upgrade could not replace it and an uninstall would leave
; it behind. The tray holds no state and the service keeps protecting;
; that user's icon comes back at their next sign-in.
!macro CloseTray
  DetailPrint "$(ClosingTray)"
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM leakguard-tray.exe'
  Pop $0
!macroend

Section "leakguard" SecMain
  SectionIn RO
  SetRegView 64
  SetShellVarContext all
  !insertmacro CloseTray

  SetOutPath "$INSTDIR"
  File "/oname=leakguard.exe" "${BINDIR}/leakguard.exe"
  File "/oname=leakguard-tray.exe" "${BINDIR}/leakguard-tray.exe"
  File "/oname=LICENSE.txt" "${LICENSEFILE}"
  !ifdef GUIDE
    File "/oname=install-windows.md" "${GUIDE}"
  !endif
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateShortcut "$SMPROGRAMS\leakguard.lnk" "$INSTDIR\leakguard-tray.exe"

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$\"$INSTDIR\leakguard-tray.exe$\""
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "URLInfoAbout" "https://github.com/Isaacpaezz/leakguard"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" "$0"

  ; An upgrade: the service runs its own copy in $INSTDIR\service, which
  ; reinstall-service replaces with the new leakguard.exe before it
  ; restarts the service. The filters stay loaded meanwhile. A failure
  ; keeps the new files but exits with 3, and the message says whether
  ; the service runs, never which version: reinstall-service may fail
  ; after it replaced the copy. A service still starting (the recovery
  ; restarts it after 5 s) gets up to 10 s to reach running, and counts
  ; as running if it is still starting then.
  ClearErrors
  ReadRegStr $0 HKLM "${SERVICEKEY}" "ImagePath"
  ${IfNot} ${Errors}
    DetailPrint "$(UpdatingService)"
    nsExec::ExecToLog '"$INSTDIR\leakguard.exe" reinstall-service'
    Pop $0
    ${If} $0 != "0"
      Call ServiceState
      ${For} $6 1 20
        ${If} $1 != 2
          ${ExitFor}
        ${EndIf}
        Sleep 500
        Call ServiceState
      ${Next}
      ; Still starting after 10 s counts as running: it is coming up.
      ${If} $1 == 4
      ${OrIf} $1 == 2
        MessageBox MB_OK|MB_ICONEXCLAMATION "$(ServiceNotUpdated)" /SD IDOK
      ${Else}
        MessageBox MB_OK|MB_ICONSTOP "$(ServiceNotRunning)" /SD IDOK
      ${EndIf}
      SetErrorLevel 3
    ${EndIf}
  ${EndIf}
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all

  ; disable stops and deletes the service, removes its copy and the
  ; filters. It runs even without a service: persistent WFP filters left
  ; behind would keep the protected services blocked with no app to lift
  ; them. When it fails no file is removed, not even the tray, so the user
  ; can retry from Settings or with the kept CLI; the uninstall fails. A
  ; failed disable may already have deleted the service while the filters
  ; stay (fail closed: the protected services stay blocked), so the
  ; message says the protection could not be removed completely, never
  ; that nothing changed.
  DetailPrint "$(RemovingService)"
  nsExec::ExecToLog '"$INSTDIR\leakguard.exe" disable'
  Pop $0
  ${If} $0 != "0"
    MessageBox MB_OK|MB_ICONSTOP "$(ServiceNotRemoved)" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}

  !insertmacro CloseTray

  Delete "$INSTDIR\leakguard.exe"
  Delete "$INSTDIR\leakguard-tray.exe"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\install-windows.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR\service"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\leakguard.lnk"
  DeleteRegValue HKCU "${RUNKEY}" "leakguard"
  DeleteRegKey HKLM "${UNINSTKEY}"
SectionEnd
