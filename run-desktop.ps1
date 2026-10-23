# Meikova Auth Desktop Shell Launcher
param(
    [switch]$BrowserOnly,
    [int]$Port = 0
)

$params = @()
if ($BrowserOnly) { $params += "--browser-only" }
if ($Port -gt 0) { $params += "--port", $Port }

Write-Host "[MEIKOVA AUTH] Khoi chay ung dung Desktop..." -ForegroundColor Cyan
python "$PSScriptRoot\meikova_auth_desktop.py" @params
