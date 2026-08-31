param(
  [string]$Binary = ".\neonet.exe",
  [string]$Bootstrap = ""
)
$ErrorActionPreference = "Stop"
$Prefix = "$env:ProgramFiles\NeoNet"
$State = "$env:ProgramData\NeoNet"
New-Item -ItemType Directory -Force $Prefix | Out-Null
New-Item -ItemType Directory -Force $State | Out-Null
Copy-Item $Binary "$Prefix\neonet.exe" -Force
if ($Bootstrap) { Copy-Item $Bootstrap "$State\bootstrap.json" -Force }

sc.exe create NeoNet binPath= "`"$Prefix\neonet.exe`" core --listen 0.0.0.0:4242" start= auto | Out-Null
sc.exe failure NeoNet reset= 86400 actions= restart/2000/restart/5000/restart/10000 | Out-Null
sc.exe start NeoNet | Out-Null
Write-Host "NeoNet installed as a Windows service."
