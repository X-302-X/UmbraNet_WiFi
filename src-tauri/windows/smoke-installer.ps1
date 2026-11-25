param([Parameter(Mandatory = $true)][string]$Installer)
$ErrorActionPreference = 'Stop'
$install = Join-Path $env:RUNNER_TEMP ("UmbraInstallTest-" + [guid]::NewGuid().ToString('N'))
$appearanceDir = Join-Path $env:APPDATA 'UmbraNet_WiFi'
$appearanceFile = Join-Path $appearanceDir 'appearance.json'
if (Test-Path -LiteralPath $appearanceDir) { throw 'Runner must not have pre-existing appearance settings' }
New-Item -ItemType Directory -Path $appearanceDir | Out-Null
Set-Content -LiteralPath $appearanceFile -Value '{"transparency":17}' -NoNewline
function Require-Appearance {
    if (!(Test-Path -LiteralPath $appearanceFile -PathType Leaf) -or (Get-Content -Raw -LiteralPath $appearanceFile) -ne '{"transparency":17}') {
        throw 'Installation or uninstall modified saved appearance settings'
    }
}

function Install-Test {
    $proc = Start-Process -FilePath $Installer -ArgumentList "/S /NS /D=$install" -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Installer failed: $($proc.ExitCode)" }
}
function Require-File([string]$path) {
    if (!(Test-Path -LiteralPath (Join-Path $install $path) -PathType Leaf)) { throw "Missing installed file: $path" }
}

Install-Test
@('umbranet-wifi.exe', 'uninstall.exe', 'core/dpi/driver/loopback_probe.exe', 'core/dpi/driver/WinDivert.dll',
  'core/dpi/driver/WinDivert64.sys', 'core/dpi/driver/LICENSE-WinDivert.txt',
  'core/dpi/driver/NOTICE.txt', 'strtegs_Uz/pass-through.json',
  'strtegs_Uz/discord-voice.json', 'strtegs_Uz/quic-bypass.json',
  'strtegs_Uz/youtube-discord-ultra.json', 'strtegs_Uz/uz1.json') | ForEach-Object { Require-File $_ }
if (Test-Path (Join-Path $install 'core/dpi/defaults/pass-through.json')) { throw 'Duplicate default strategy is present' }
if (!(Test-Path (Join-Path $install 'logs') -PathType Container)) { throw 'Missing logs directory' }
$expected = @{
    'core/dpi/driver/WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'core/dpi/driver/WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
    'strtegs_Uz/uz1.json' = '3865657c401fe13b6c30a0ca0fd280345d4c50a3759c60492de886b4ada8efe9'
}
foreach ($file in $expected.Keys) {
    $actual = (Get-FileHash (Join-Path $install $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$file]) {
        $sourcePath = Join-Path (Join-Path $PSScriptRoot '../..') $file
        $sourceHash = if (Test-Path -LiteralPath $sourcePath -PathType Leaf) { (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() } else { 'missing' }
        throw "Incorrect installed file: $file; expected SHA-256 $($expected[$file]); installed $actual; source $sourceHash"
    }
}
$helperSource = Join-Path $PSScriptRoot '../../core/dpi/target/x86_64-pc-windows-msvc/release/examples/loopback_probe.exe'
$helperInstalled = Join-Path $install 'core/dpi/driver/loopback_probe.exe'
if ((Get-FileHash -LiteralPath $helperSource -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $helperInstalled -Algorithm SHA256).Hash) {
    throw 'Installed loopback helper differs from the built helper'
}
# Reinstall without touching user-modified strategies or user-generated data.
Set-Content -LiteralPath (Join-Path $install 'strtegs_Uz/pass-through.json') -Value 'user strategy' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'strtegs_Uz/custom.json') -Value 'user custom' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'strtegs_Uz/quic-bypass.json') -Value 'user quic strategy' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'strtegs_Uz/uz1.json') -Value 'user uz1 strategy' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'core/dpi/selection.json') -Value 'user selection' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'logs/test.txt') -Value 'user log' -NoNewline
Install-Test
Require-Appearance
foreach ($pair in @(@('strtegs_Uz/pass-through.json','user strategy'), @('strtegs_Uz/custom.json','user custom'), @('strtegs_Uz/quic-bypass.json','user quic strategy'), @('strtegs_Uz/uz1.json','user uz1 strategy'), @('core/dpi/selection.json','user selection'), @('logs/test.txt','user log'))) {
    if ((Get-Content -Raw -LiteralPath (Join-Path $install $pair[0])) -ne $pair[1]) { throw "Reinstall changed user file: $($pair[0])" }
}
# Uninstaller should remove app files but not the user's selections, strategies or logs.
$uninstall = Join-Path $install 'uninstall.exe'
$proc = Start-Process -FilePath $uninstall -ArgumentList "/S _?=$install" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "Uninstaller failed: $($proc.ExitCode)" }
foreach ($path in @('strtegs_Uz/pass-through.json','strtegs_Uz/custom.json','strtegs_Uz/quic-bypass.json','strtegs_Uz/uz1.json','core/dpi/selection.json','logs/test.txt')) {
    Require-File $path
}
if (Test-Path (Join-Path $install 'umbranet-wifi.exe')) { throw 'Uninstall did not remove the executable' }
if (Test-Path -LiteralPath (Join-Path $install 'core/dpi/driver/WinDivert64.sys')) { throw 'Uninstall left the unlocked driver file' }
Require-Appearance
Write-Host 'Installer, reinstall and uninstall without data deletion: OK'
# Reinstall over preserved data, then test the full-delete branch without a desktop.
Install-Test
Require-Appearance
& (Join-Path $PSScriptRoot 'smoke-full-uninstall.ps1') -Install $install -AppearanceDir $appearanceDir
# A fresh installation after full removal must not revive prior data.
Install-Test
@('strtegs_Uz/pass-through.json', 'strtegs_Uz/discord-voice.json', 'strtegs_Uz/quic-bypass.json', 'strtegs_Uz/youtube-discord-ultra.json', 'strtegs_Uz/uz1.json') | ForEach-Object { Require-File $_ }
if ((Get-Content -Raw -LiteralPath (Join-Path $install 'strtegs_Uz/quic-bypass.json')) -eq 'user quic strategy') { throw 'Fresh install revived modified QUIC strategy' }
if ((Get-Content -Raw -LiteralPath (Join-Path $install 'strtegs_Uz/uz1.json')) -eq 'user uz1 strategy') { throw 'Fresh install revived modified Uz1 strategy' }
if (Test-Path -LiteralPath $appearanceDir) { throw 'Fresh install revived appearance data' }
if (Test-Path -LiteralPath (Join-Path $install 'strtegs_Uz/custom.json')) { throw 'Fresh install revived user strategies' }
if (Test-Path -LiteralPath (Join-Path $install 'core/dpi/selection.json')) { throw 'Fresh install revived selections' }
if ((Get-Content -Raw -LiteralPath (Join-Path $install 'strtegs_Uz/pass-through.json')) -eq 'user strategy') { throw 'Fresh install revived modified strategy' }
$proc = Start-Process -FilePath (Join-Path $install 'uninstall.exe') -ArgumentList "/S _?=$install" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw 'Final test uninstall failed' }
Remove-Item -LiteralPath $install -Recurse -Force
Write-Host 'Fresh installation after full uninstall: OK'

# Simulate a locked file, not a loaded kernel driver. The uninstaller must not
# report success or schedule deletion of a future replacement at the same path.
Install-Test
$driver = Join-Path $install 'core/dpi/driver/WinDivert64.sys'
$lock = [System.IO.File]::Open($driver, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
try {
    $proc = Start-Process -FilePath (Join-Path $install 'uninstall.exe') -ArgumentList "/S _?=$install" -Wait -PassThru
    if ($proc.ExitCode -eq 0) { throw 'Uninstaller reported success although the driver file was locked' }
    if (!(Test-Path -LiteralPath $driver -PathType Leaf)) { throw 'Locked driver file unexpectedly disappeared' }
} finally {
    $lock.Dispose()
}
Remove-Item -LiteralPath $install -Recurse -Force
Write-Host 'Locked-file uninstall reports failure: OK (not a test with a loaded driver)'
