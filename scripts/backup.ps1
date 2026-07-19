param(
  [string]$InstancePath = "instance",
  [string]$Destination = "backups"
)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dest = Join-Path $Destination "cyberinvestigator-$timestamp"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path (Join-Path $InstancePath "cyberinvestigator.db") -Destination $dest -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $InstancePath "reports") -Destination $dest -Recurse -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $InstancePath "uploads") -Destination $dest -Recurse -ErrorAction SilentlyContinue
Write-Output "Backup created at $dest"
