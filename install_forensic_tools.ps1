$ErrorActionPreference = "Stop"

$toolsDir = "d:\ARGUS\external_tools"
if (!(Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
}

Write-Host "Installing Python requirements..."
pip install -r d:\ARGUS\requirements-forensics.txt

Write-Host "Downloading Eric Zimmerman Tools..."
$ezToolsDir = Join-Path $toolsDir "ZimmermanTools"
if (!(Test-Path $ezToolsDir)) {
    New-Item -ItemType Directory -Force -Path $ezToolsDir | Out-Null
}
$ezScript = Join-Path $toolsDir "Get-ZimmermanTools.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" -OutFile $ezScript
# Unblock the script
Unblock-File -Path $ezScript
# Run the script to download to the ezToolsDir
& $ezScript -Dest $ezToolsDir

Write-Host "Downloading Hayabusa..."
$hayabusaDir = Join-Path $toolsDir "Hayabusa"
if (!(Test-Path $hayabusaDir)) {
    New-Item -ItemType Directory -Force -Path $hayabusaDir | Out-Null
}
# We'll just download a known release, e.g., 3.6.0 (or whatever is latest, but we'll hardcode one that is likely available)
$hayabusaZip = Join-Path $toolsDir "hayabusa.zip"
Invoke-WebRequest -Uri "https://github.com/Yamato-Security/hayabusa/releases/download/v3.8.0/hayabusa-3.8.0-win-x64.zip" -OutFile $hayabusaZip
Expand-Archive -Path $hayabusaZip -DestinationPath $hayabusaDir -Force
Remove-Item $hayabusaZip
# Run hayabusa to update rules
$hayabusaExe = Get-ChildItem -Path $hayabusaDir -Filter "hayabusa*.exe" -Recurse | Select-Object -First 1
if ($hayabusaExe) {
    & $hayabusaExe.FullName update-rules
}

Write-Host "Downloading RegRipper..."
$regRipperDir = Join-Path $toolsDir "RegRipper"
$regRipperZip = Join-Path $toolsDir "regripper.zip"
Invoke-WebRequest -Uri "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip" -OutFile $regRipperZip
Expand-Archive -Path $regRipperZip -DestinationPath $toolsDir -Force
Remove-Item $regRipperZip
Rename-Item -Path (Join-Path $toolsDir "RegRipper3.0-master") -NewName "RegRipper"

Write-Host "Downloading Volatility 3 ISF Symbols..."
$volDir = Join-Path $toolsDir "symbols"
if (!(Test-Path $volDir)) {
    New-Item -ItemType Directory -Force -Path $volDir | Out-Null
}
$winSymbolsZip = Join-Path $toolsDir "windows.zip"
# Fetch from a known source for ISF symbols (e.g. standard volatility3 windows symbols)
try {
    Invoke-WebRequest -Uri "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip" -OutFile $winSymbolsZip
    Expand-Archive -Path $winSymbolsZip -DestinationPath $volDir -Force
    Remove-Item $winSymbolsZip
} catch {
    Write-Host "Warning: Could not download windows.zip symbols. You may need to obtain them manually."
}

Write-Host "Done!"
