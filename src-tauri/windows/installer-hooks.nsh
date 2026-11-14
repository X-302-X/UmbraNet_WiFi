; Use native separators: Windows NSIS must open this file while compiling Setup.
!define UMBRA_INITIAL_STRATEGY "${__FILEDIR__}\..\..\strtegs_Uz\pass-through.json"

; User strategies and logs are preserved during installation and updates.
!macro NSIS_HOOK_POSTINSTALL
  ClearErrors
  CreateDirectory "$INSTDIR\strtegs_Uz"
  CreateDirectory "$INSTDIR\logs"
  IfErrors 0 +2
    Abort "Cannot create application directories."
  ; Extract the bundled example only if the user does not already have it.
  IfFileExists "$INSTDIR\strtegs_Uz\pass-through.json" umbra_strategy_done 0
    ClearErrors
    SetOutPath "$INSTDIR\strtegs_Uz"
    File /oname=pass-through.json "${UMBRA_INITIAL_STRATEGY}"
    IfErrors 0 umbra_strategy_done
    Abort "Cannot create the initial strategy file."
  umbra_strategy_done:
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
