; Resolve this include's directory now, not when the macro is expanded by Tauri.
!define UMBRA_STRATEGY_SOURCE "${__FILEDIR__}\..\..\strtegs_Uz"
; A bundled example is added only when a file by that name does not already exist.
!macro UMBRA_INSTALL_STRATEGY ID NAME
  IfFileExists "$INSTDIR\strtegs_Uz\${NAME}" umbra_strategy_${ID}_done 0
    ClearErrors
    SetOutPath "$INSTDIR\strtegs_Uz"
    File /oname=${NAME} "${UMBRA_STRATEGY_SOURCE}\${NAME}"
    IfErrors 0 umbra_strategy_${ID}_done
    Abort "Cannot create bundled strategy ${NAME}."
  umbra_strategy_${ID}_done:
!macroend

; User strategies and logs are preserved during installation and updates.
!macro NSIS_HOOK_POSTINSTALL
  ClearErrors
  CreateDirectory "$INSTDIR\strtegs_Uz"
  CreateDirectory "$INSTDIR\logs"
  IfErrors 0 +2
    Abort "Cannot create application directories."
  !insertmacro UMBRA_INSTALL_STRATEGY "pass" "pass-through.json"
  !insertmacro UMBRA_INSTALL_STRATEGY "voice" "discord-voice.json"
  !insertmacro UMBRA_INSTALL_STRATEGY "quic" "quic-bypass.json"
  !insertmacro UMBRA_INSTALL_STRATEGY "yt" "youtube-discord-ultra.json"
  SetOutPath "$INSTDIR"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "Будут удалены настройки, стратегии и логи UmbraNet. Восстановить их не получится. Продолжить?" IDYES umbra_full_delete_confirmed
    Abort
    umbra_full_delete_confirmed:
  ${EndIf}
!macroend

; Tauri's confirmation checkbox is the sole opt-in to removing user data.
; Silent removals, updates and reinstalls must never remove it.
!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    ClearErrors
    RmDir /r "$APPDATA\UmbraNet_WiFi"
    RmDir /r "$INSTDIR\strtegs_Uz"
    RmDir /r "$INSTDIR\logs"
    Delete "$INSTDIR\core\dpi\services.json"
    Delete "$INSTDIR\core\dpi\selection.json"
    Delete "$INSTDIR\core\dpi\active-domains.txt"
    Delete "$INSTDIR\data\core\dpi\services.json"
    Delete "$INSTDIR\data\core\dpi\selection.json"
    Delete "$INSTDIR\data\core\dpi\active-domains.txt"
    RmDir "$INSTDIR\data\core\dpi"
    RmDir "$INSTDIR\data\core"
    RmDir "$INSTDIR\data"
    RmDir "$INSTDIR\core\dpi\driver"
    RmDir "$INSTDIR\core\dpi"
    RmDir "$INSTDIR\core"
    RmDir "$INSTDIR"
    ; Report locked or inaccessible user data instead of claiming it was removed.
    IfFileExists "$APPDATA\UmbraNet_WiFi\*.*" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\strtegs_Uz\*.*" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\logs\*.*" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\core\dpi\services.json" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\core\dpi\selection.json" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\core\dpi\active-domains.txt" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\data\core\dpi\services.json" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\data\core\dpi\selection.json" umbra_cleanup_failed 0
    IfFileExists "$INSTDIR\data\core\dpi\active-domains.txt" umbra_cleanup_failed 0
    IfFileExists "$APPDATA\${BUNDLEID}\*.*" umbra_cleanup_failed 0
    IfFileExists "$LOCALAPPDATA\${BUNDLEID}\*.*" umbra_cleanup_failed 0
    Goto umbra_cleanup_done
    umbra_cleanup_failed:
      SetErrorLevel 1
      IfSilent umbra_cleanup_done 0
      MessageBox MB_ICONEXCLAMATION "Не удалось удалить все данные UmbraNet. Закройте программу и проверьте папки настроек и установки."
    umbra_cleanup_done:
  ${EndIf}
!macroend
