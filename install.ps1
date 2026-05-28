$ErrorActionPreference = "Stop"
$version = "v1.0.6"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$url = "https://github.com/KatrielMoses/PhoneAccess/releases/download/$version/phoneaccess_windows_$arch.exe"

Write-Host "Installing PhoneAccess $version..." -ForegroundColor Cyan

# Prefer updating an existing install location over creating a new one
$existing = Get-Command phoneaccess -ErrorAction SilentlyContinue
$gobin = if ($env:GOPATH) { "$env:GOPATH\bin" } elseif (Test-Path "$env:USERPROFILE\go\bin") { "$env:USERPROFILE\go\bin" } else { $null }

if ($existing) {
    $bin = $existing.Source
    Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing
    Write-Host "Updated $bin" -ForegroundColor Cyan
} elseif ($gobin -and ($env:PATH -like "*$gobin*")) {
    $bin = "$gobin\phoneaccess.exe"
    Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing
    Write-Host "Installed to $bin" -ForegroundColor Cyan
} else {
    $dest = "$env:LOCALAPPDATA\PhoneAccess"
    $bin = "$dest\phoneaccess.exe"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing
    $path = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($path -notlike "*$dest*") {
        [Environment]::SetEnvironmentVariable("PATH", "$dest;$path", "User")
        $env:PATH = "$dest;$env:PATH"
        Write-Host "Added to PATH. Restart your terminal." -ForegroundColor Yellow
    }
}

Write-Host "Done. Run: phoneaccess version" -ForegroundColor Green
