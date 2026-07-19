param(
  [Parameter(Mandatory = $true)][string]$BackupPath,
  [string]$InstancePath = "instance"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $InstancePath | Out-Null
Copy-Item -Path (Join-Path $BackupPath "cyberinvestigator.db") -Destination (Join-Path $InstancePath "cyberinvestigator.db") -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $BackupPath "reports") -Destination $InstancePath -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $BackupPath "uploads") -Destination $InstancePath -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "Recovery completed from $BackupPath"
