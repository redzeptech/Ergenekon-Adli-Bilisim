# ftools icine depodaki sabit icerikleri kopyalar (yardim HTML).
# Ikili arac dosyalarini hala ust kaynaktan (forensictools) ftools altina kendiniz koymalisiniz.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$HelpSrc = Join-Path $Root "docs\help\help.html"
$HelpDstDir = Join-Path $Root "ftools\help"
if (-not (Test-Path $HelpSrc)) {
    Write-Error "Bulunamadi: $HelpSrc"
}
New-Item -ItemType Directory -Force -Path $HelpDstDir | Out-Null
Copy-Item -LiteralPath $HelpSrc -Destination (Join-Path $HelpDstDir "help.html") -Force
Write-Host "Tamam: docs\help\help.html -> ftools\help\help.html"
