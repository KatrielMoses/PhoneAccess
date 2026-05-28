$ErrorActionPreference = "Stop"
$version = "v1.0.0"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$url = "https://github.com/KatrielMoses/PhoneAccess/releases/download/$version/phoneaccess_windows_$arch.exe"
$dest = "$env:LOCALAPPDATA\PhoneAccess"
$bin = "$dest\phoneaccess.exe"

Write-Host "Installing PhoneAccess $version..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing

$path = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($path -notlike "*$dest*") {
    [Environment]::SetEnvironmentVariable("PATH", "$path;$dest", "User")
    Write-Host "Added to PATH. Restart your terminal." -ForegroundColor Yellow
}

Write-Host "Done. Run: phoneaccess version" -ForegroundColor Green
