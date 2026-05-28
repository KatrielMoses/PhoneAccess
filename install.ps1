$ErrorActionPreference = "Stop"
$version = "v1.0.3"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$url = "https://github.com/KatrielMoses/PhoneAccess/releases/download/$version/phoneaccess_windows_$arch.exe"
$dest = "$env:LOCALAPPDATA\PhoneAccess"
$bin = "$dest\phoneaccess.exe"

Write-Host "Installing PhoneAccess $version..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing

# If phoneaccess is already on PATH somewhere else, update that copy too
$existing = Get-Command phoneaccess -ErrorAction SilentlyContinue
if ($existing -and $existing.Source -ne $bin) {
    Copy-Item $bin $existing.Source -Force
    Write-Host "Updated existing install at $($existing.Source)" -ForegroundColor Cyan
}

# Prepend to PATH so this version takes priority
$path = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($path -notlike "*$dest*") {
    [Environment]::SetEnvironmentVariable("PATH", "$dest;$path", "User")
}

# Update current session PATH immediately — no terminal restart needed
$env:PATH = "$dest;" + ($env:PATH -replace [regex]::Escape("$dest;"), "")

Write-Host "Done. Run: phoneaccess version" -ForegroundColor Green
