; User strategies and logs are not bundled resources and are never deleted here.
!macro NSIS_HOOK_POSTINSTALL
  ClearErrors
  CreateDirectory "$INSTDIR\strtegs_Uz"
  CreateDirectory "$INSTDIR\logs"
  IfErrors 0 +2
    Abort "Cannot create application directories."
  ; Copy the example only once: never overwrite a user's existing strategy.
  IfFileExists "$INSTDIR\strtegs_Uz\pass-through.json" umbra_strategy_done 0
    ClearErrors
    CopyFiles /SILENT "$INSTDIR\core\dpi\defaults\pass-through.json" "$INSTDIR\strtegs_Uz"
    IfErrors 0 umbra_strategy_done
    Abort "Cannot create the initial strategy file."
  umbra_strategy_done:
!macroend
