param(
    [Parameter(Mandatory = $true)][string]$Install,
    [Parameter(Mandatory = $true)][string]$AppearanceDir
)
$ErrorActionPreference = 'Stop'

# Recompile the exact Tauri-generated NSIS script as a *test-only* installer.
# It sets the state normally read from the confirmation checkbox and skips the
# warning dialog, so the deletion logic can be exercised in a headless runner.
# The production installer and its confirmation remain unchanged.
$generated = Join-Path $PSScriptRoot '../target/x86_64-pc-windows-msvc/release/nsis/x64/installer.nsi'
$compiler = Join-Path $env:LOCALAPPDATA 'tauri/NSIS/makensis.exe'
if (!(Test-Path -LiteralPath $generated -PathType Leaf)) { throw "Tauri-generated NSIS script not found: $generated" }
if (!(Test-Path -LiteralPath $compiler -PathType Leaf)) { throw "Tauri NSIS compiler not found: $compiler" }
$source = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $generated).Path)
$checkboxRead = 'SendMessage $DeleteAppDataCheckbox ${BM_GETCHECK} 0 0 $DeleteAppDataCheckboxState'
if (!$source.Contains($checkboxRead)) { throw 'Tauri checkbox state handler changed; review full-uninstall test' }
$sectionPattern = '(?ms)^Section Uninstall\s+!ifmacrodef NSIS_HOOK_PREUNINSTALL\s+!insertmacro NSIS_HOOK_PREUNINSTALL\s+!endif'
$sections = [regex]::Matches($source, $sectionPattern)
if ($sections.Count -ne 1) { throw 'Tauri uninstall hook layout changed; review full-uninstall test' }
$outputPattern = '(?m)^!define OUTFILE "[^"\r\n]*"'
if ([regex]::Matches($source, $outputPattern).Count -ne 1) { throw 'Tauri NSIS output definition changed' }
$testInstaller = Join-Path $env:RUNNER_TEMP ("umbra-full-delete-test-" + [guid]::NewGuid().ToString('N') + '.exe')
$testScript = Join-Path (Split-Path -Parent $generated) 'installer-full-delete-test.nsi'
$source = $source.Replace($sections[0].Value, "Section Uninstall`r`n  StrCpy `$DeleteAppDataCheckboxState 1")
$source = [regex]::Replace($source, $outputPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($match) '!define OUTFILE "' + $testInstaller + '"' })
[System.IO.File]::WriteAllText($testScript, $source, [System.Text.UTF8Encoding]::new($true))
try {
    & $compiler /V2 $testScript
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $testInstaller -PathType Leaf)) { throw 'Failed to compile test-only NSIS installer' }
    $proc = Start-Process -FilePath $testInstaller -ArgumentList "/S /NS /D=$Install" -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Test-only installer failed: $($proc.ExitCode)" }
} finally {
    Remove-Item -LiteralPath $testScript, $testInstaller -Force -ErrorAction SilentlyContinue
}

$roamingWebview = Join-Path $env:APPDATA 'org.umbranet.wifi'
$localWebview = Join-Path $env:LOCALAPPDATA 'org.umbranet.wifi'
foreach ($path in @($roamingWebview, $localWebview)) {
    if (Test-Path -LiteralPath $path) { throw "Runner must not contain existing WebView data: $path" }
    New-Item -ItemType Directory -Path $path | Out-Null
    Set-Content -LiteralPath (Join-Path $path 'smoke-marker.txt') -Value 'test' -NoNewline
}
New-Item -ItemType Directory -Force -Path (Join-Path $Install 'data/core/dpi') | Out-Null
foreach ($path in @('core/dpi/services.json','core/dpi/active-domains.txt', 'data/core/dpi/selection.json','data/core/dpi/services.json','data/core/dpi/active-domains.txt')) {
    Set-Content -LiteralPath (Join-Path $Install $path) -Value 'test' -NoNewline
}
# Files outside the application-owned paths must not be deleted.
Set-Content -LiteralPath (Join-Path $Install 'unrelated-user-file.txt') -Value 'keep' -NoNewline
$uninstall = Join-Path $Install 'uninstall.exe'
$proc = Start-Process -FilePath $uninstall -ArgumentList "/S _?=$Install" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "Full-delete test uninstaller failed: $($proc.ExitCode)" }
foreach ($path in @($AppearanceDir, $roamingWebview, $localWebview, (Join-Path $Install 'strtegs_Uz'), (Join-Path $Install 'logs'), (Join-Path $Install 'core/dpi/selection.json'), (Join-Path $Install 'core/dpi/services.json'), (Join-Path $Install 'core/dpi/active-domains.txt'), (Join-Path $Install 'data/core/dpi/selection.json'), (Join-Path $Install 'data/core/dpi/services.json'), (Join-Path $Install 'data/core/dpi/active-domains.txt'))) {
    if (Test-Path -LiteralPath $path) { throw "Full uninstall left application data: $path" }
}
if (Test-Path -LiteralPath (Join-Path $Install 'core/dpi/driver/WinDivert64.sys')) { throw 'Full uninstall left the unlocked driver file' }
if (!(Test-Path -LiteralPath (Join-Path $Install 'unrelated-user-file.txt') -PathType Leaf)) { throw 'Full uninstall deleted an unrelated file' }
Remove-Item -LiteralPath $Install -Recurse -Force
Write-Host 'Headless full-uninstall data cleanup: OK (UI confirmation requires manual Windows test)'
