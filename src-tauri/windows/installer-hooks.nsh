; Capture the hook's directory before the macro is expanded in Tauri's script.
!define UMBRA_INITIAL_STRATEGY "${__FILEDIR__}/../../strtegs_Uz/pass-through.json"

; User strategies and logs are not bundled resources and are never deleted here.
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
