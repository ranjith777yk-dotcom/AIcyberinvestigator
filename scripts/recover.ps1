param(
  [Parameter(Mandatory = $true)][string]$BackupPath,
  [string]$InstancePath = "instance",
  [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$resolvedBackup = (Resolve-Path -LiteralPath $BackupPath).Path
$manifestPath = Join-Path $resolvedBackup "manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
  throw "Restore refused: manifest.json is unavailable."
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($record in $manifest.files) {
  $target = [System.IO.Path]::GetFullPath((Join-Path $resolvedBackup $record.path))
  if (-not $target.StartsWith($resolvedBackup, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Restore refused: manifest path escapes the backup root."
  }
  if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw "Restore refused: missing file $($record.path)."
  }
  $actualHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
  $actualSize = (Get-Item -LiteralPath $target).Length
  if ($actualHash -ne $record.sha256 -or $actualSize -ne $record.size_bytes) {
    throw "Restore refused: integrity mismatch for $($record.path)."
  }
}

Write-Output "Backup $($manifest.backup_id) passed verification for $($manifest.file_count) files."
if ($VerifyOnly) {
  return
}

New-Item -ItemType Directory -Force -Path $InstancePath | Out-Null
$database = Join-Path $resolvedBackup "database\cyberinvestigator.db"
if (Test-Path -LiteralPath $database -PathType Leaf) {
  Copy-Item -LiteralPath $database -Destination (Join-Path $InstancePath "cyberinvestigator.db") -Force
}
$reports = Join-Path $resolvedBackup "data\reports"
if (Test-Path -LiteralPath $reports -PathType Container) {
  $reportTarget = Join-Path $InstancePath "reports"
  New-Item -ItemType Directory -Force -Path $reportTarget | Out-Null
  Get-ChildItem -LiteralPath $reports | Copy-Item -Destination $reportTarget -Recurse -Force
}
$evidence = Join-Path $resolvedBackup "data\evidence-quarantine"
if (Test-Path -LiteralPath $evidence -PathType Container) {
  $uploadTarget = Join-Path $InstancePath "uploads"
  $quarantineTarget = Join-Path $uploadTarget "quarantine"
  New-Item -ItemType Directory -Force -Path $quarantineTarget | Out-Null
  Get-ChildItem -LiteralPath $evidence | Copy-Item -Destination $quarantineTarget -Recurse -Force
}
Write-Output "Recovery completed from verified backup $($manifest.backup_id)."
Write-Warning "Run this workflow only while application workers are stopped, then verify database, evidence, and audit integrity."
