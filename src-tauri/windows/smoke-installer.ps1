param([Parameter(Mandatory = $true)][string]$Installer)
$ErrorActionPreference = 'Stop'
$install = Join-Path $env:RUNNER_TEMP ("UmbraInstallTest-" + [guid]::NewGuid().ToString('N'))

function Install-Test {
    $proc = Start-Process -FilePath $Installer -ArgumentList "/S /NS /D=$install" -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Installer failed: $($proc.ExitCode)" }
}
function Require-File([string]$path) {
    if (!(Test-Path -LiteralPath (Join-Path $install $path) -PathType Leaf)) { throw "Missing installed file: $path" }
}

Install-Test
@('umbranet-wifi.exe', 'uninstall.exe', 'core/dpi/driver/WinDivert.dll',
  'core/dpi/driver/WinDivert64.sys', 'core/dpi/driver/LICENSE-WinDivert.txt',
  'core/dpi/driver/NOTICE.txt', 'core/dpi/defaults/pass-through.json',
  'strtegs_Uz/pass-through.json') | ForEach-Object { Require-File $_ }
if (!(Test-Path (Join-Path $install 'logs') -PathType Container)) { throw 'Missing logs directory' }
$expected = @{
    'core/dpi/driver/WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'core/dpi/driver/WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
foreach ($file in $expected.Keys) {
    $actual = (Get-FileHash (Join-Path $install $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$file]) { throw "Incorrect installed WinDivert file: $file" }
}
# Reinstall without touching user-modified strategies or user-generated data.
Set-Content -LiteralPath (Join-Path $install 'strtegs_Uz/pass-through.json') -Value 'user strategy' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'strtegs_Uz/custom.json') -Value 'user custom' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'core/dpi/selection.json') -Value 'user selection' -NoNewline
Set-Content -LiteralPath (Join-Path $install 'logs/test.txt') -Value 'user log' -NoNewline
Install-Test
foreach ($pair in @(@('strtegs_Uz/pass-through.json','user strategy'), @('strtegs_Uz/custom.json','user custom'), @('core/dpi/selection.json','user selection'), @('logs/test.txt','user log'))) {
    if ((Get-Content -Raw -LiteralPath (Join-Path $install $pair[0])) -ne $pair[1]) { throw "Reinstall changed user file: $($pair[0])" }
}
# Uninstaller should remove app files but not the user's selections, strategies or logs.
$uninstall = Join-Path $install 'uninstall.exe'
$proc = Start-Process -FilePath $uninstall -ArgumentList "/S _?=$install" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "Uninstaller failed: $($proc.ExitCode)" }
foreach ($path in @('strtegs_Uz/pass-through.json','strtegs_Uz/custom.json','core/dpi/selection.json','logs/test.txt')) {
    Require-File $path
}
if (Test-Path (Join-Path $install 'umbranet-wifi.exe')) { throw 'Uninstall did not remove the executable' }
Write-Host 'Installer, reinstall, uninstall and user-data preservation: OK'
