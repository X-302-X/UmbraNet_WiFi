param(
    [Parameter(Mandatory = $true)][string]$Install,
    [Parameter(Mandatory = $true)][string]$AppearanceDir
)
$ErrorActionPreference = 'Stop'
# This test controls the actual NSIS confirmation page, not a simulated switch.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class UmbraUninstallUi {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc callback, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int size);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int size);
    [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h, int index);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint message, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint message, IntPtr w, IntPtr l);
    public static IntPtr[] Dialogs(uint pid) {
        var result = new List<IntPtr>();
        EnumWindows((h,l) => { uint id; GetWindowThreadProcessId(h, out id); var cls = new StringBuilder(64); GetClassName(h, cls, cls.Capacity); if (id == pid && IsWindowVisible(h) && cls.ToString() == "#32770") result.Add(h); return true; }, IntPtr.Zero);
        return result.ToArray();
    }
    public static IntPtr Checkbox(IntPtr dialog) {
        IntPtr result = IntPtr.Zero;
        EnumChildWindows(dialog, (h,l) => { var cls = new StringBuilder(64); GetClassName(h, cls, cls.Capacity); if (cls.ToString() == "Button" && (GetWindowLong(h, -16) & 15) == 3) { result = h; return false; } return true; }, IntPtr.Zero);
        return result;
    }
    public static string Text(IntPtr h) { var text = new StringBuilder(256); GetWindowText(h, text, text.Capacity); return text.ToString(); }
}
'@

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
# Unrelated files are outside the application-owned paths and must not be deleted.
Set-Content -LiteralPath (Join-Path $Install 'unrelated-user-file.txt') -Value 'keep' -NoNewline
$uninstall = Join-Path $Install 'uninstall.exe'
$proc = Start-Process -FilePath $uninstall -ArgumentList "_?=$Install" -PassThru
try {
    $main = [IntPtr]::Zero
    $checkbox = [IntPtr]::Zero
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        if ($proc.HasExited) { throw 'Uninstaller exited before its confirmation page appeared' }
        foreach ($dialog in [UmbraUninstallUi]::Dialogs([uint32]$proc.Id)) {
            $candidate = [UmbraUninstallUi]::Checkbox($dialog)
            if ($candidate -ne [IntPtr]::Zero) { $main = $dialog; $checkbox = $candidate; break }
        }
        if ($checkbox -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 100 }
    } while ($checkbox -eq [IntPtr]::Zero -and [DateTime]::UtcNow -lt $deadline)
    if ($checkbox -eq [IntPtr]::Zero) { throw 'Could not find the real uninstall data checkbox' }
    # Set the same check state that clicking the UI would produce; the page leave handler reads it.
    [void][UmbraUninstallUi]::SendMessage($checkbox, 0xF1, [IntPtr]1, [IntPtr]::Zero)
    if ([UmbraUninstallUi]::SendMessage($checkbox, 0xF0, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32() -ne 1) { throw 'Could not check uninstall data checkbox' }
    $next = [UmbraUninstallUi]::GetDlgItem($main, 1)
    if ($next -eq [IntPtr]::Zero) { throw 'Could not find uninstall confirmation button' }
    [void][UmbraUninstallUi]::PostMessage($main, 0x111, [IntPtr]1, $next)
    $confirmed = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (!$proc.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        foreach ($dialog in [UmbraUninstallUi]::Dialogs([uint32]$proc.Id)) {
            if ($dialog -ne $main -and !$confirmed) {
                $yes = [UmbraUninstallUi]::GetDlgItem($dialog, 6)
                if ($yes -ne [IntPtr]::Zero) {
                    [void][UmbraUninstallUi]::PostMessage($dialog, 0x111, [IntPtr]6, $yes)
                    $confirmed = $true
                }
            } elseif ($dialog -eq $main -and $confirmed) {
                $button = [UmbraUninstallUi]::GetDlgItem($dialog, 1)
                $text = [UmbraUninstallUi]::Text($button).Replace('&', '')
                if ($text -in @('Close', 'Закрыть')) { [void][UmbraUninstallUi]::PostMessage($dialog, 0x111, [IntPtr]1, $button) }
            }
        }
        Start-Sleep -Milliseconds 100
        $proc.Refresh()
    }
    if (!$proc.HasExited) { throw 'Uninstaller did not finish after confirming full removal' }
    if (!$confirmed) { throw 'Full-removal warning did not appear' }
    if ($proc.ExitCode -ne 0) { throw "Full uninstaller failed: $($proc.ExitCode)" }
} finally {
    if (!$proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
foreach ($path in @($AppearanceDir, $roamingWebview, $localWebview, (Join-Path $Install 'strtegs_Uz'), (Join-Path $Install 'logs'), (Join-Path $Install 'core/dpi/selection.json'), (Join-Path $Install 'core/dpi/services.json'), (Join-Path $Install 'core/dpi/active-domains.txt'), (Join-Path $Install 'data/core/dpi/selection.json'), (Join-Path $Install 'data/core/dpi/services.json'), (Join-Path $Install 'data/core/dpi/active-domains.txt'))) {
    if (Test-Path -LiteralPath $path) { throw "Full uninstall left application data: $path" }
}
if (!(Test-Path -LiteralPath (Join-Path $Install 'unrelated-user-file.txt') -PathType Leaf)) { throw 'Full uninstall deleted an unrelated file' }
Remove-Item -LiteralPath $Install -Recurse -Force
Write-Host 'Interactive full uninstall, confirmation and user-data cleanup: OK'
