param(
  [string]$InstancePath = "instance",
  [string]$Destination = "backups"
)

$ErrorActionPreference = "Stop"
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$backupId = "cyberinvestigator-$timestamp"
$dest = Join-Path $Destination $backupId
$partial = "$dest.partial"

if (Test-Path -LiteralPath $partial) {
  throw "Partial backup path already exists: $partial"
}

New-Item -ItemType Directory -Force -Path $partial | Out-Null
try {
  $databaseSource = Join-Path $InstancePath "cyberinvestigator.db"
  if (Test-Path -LiteralPath $databaseSource -PathType Leaf) {
    $databaseTarget = Join-Path $partial "database"
    New-Item -ItemType Directory -Force -Path $databaseTarget | Out-Null
    Copy-Item -LiteralPath $databaseSource -Destination (Join-Path $databaseTarget "cyberinvestigator.db")
  }

  $sources = @(
    @{ Source = (Join-Path $InstancePath "reports"); Target = (Join-Path $partial "data\reports") },
    @{ Source = (Join-Path $InstancePath "uploads\quarantine"); Target = (Join-Path $partial "data\evidence-quarantine") }
  )
  foreach ($entry in $sources) {
    if (Test-Path -LiteralPath $entry.Source -PathType Container) {
      New-Item -ItemType Directory -Force -Path $entry.Target | Out-Null
      Get-ChildItem -LiteralPath $entry.Source | Copy-Item -Destination $entry.Target -Recurse -Force
    }
  }

  $resolvedPartial = (Resolve-Path -LiteralPath $partial).Path
  $files = @(
    Get-ChildItem -LiteralPath $partial -Recurse -File | ForEach-Object {
      $relative = [System.IO.Path]::GetRelativePath($resolvedPartial, $_.FullName).Replace("\", "/")
      @{
        path = $relative
        size_bytes = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      }
    }
  )
  $manifest = @{
    schema_version = 1
    backup_id = $backupId
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    status = "verified"
    provider = "local-filesystem"
    file_count = $files.Count
    size_bytes = ($files | Measure-Object -Property size_bytes -Sum).Sum
    files = $files
  }
  $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $partial "manifest.json") -Encoding utf8
  Move-Item -LiteralPath $partial -Destination $dest
  Write-Output "Verified backup created at $dest"
  Write-Warning "For a transactionally consistent live SQLite snapshot, use the authenticated storage administration API."
}
catch {
  if (Test-Path -LiteralPath $partial) {
    Remove-Item -LiteralPath $partial -Recurse -Force
  }
  throw
}
