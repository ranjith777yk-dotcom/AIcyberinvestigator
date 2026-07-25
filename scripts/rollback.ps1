param(
  [Parameter(Mandatory = $true)][string]$TargetVersion,
  [string]$ComposeFile = "docker-compose.yml",
  [switch]$Apply
)

$ErrorActionPreference = "Stop"
if ($TargetVersion -notmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$") {
  throw "TargetVersion contains unsupported characters."
}
if (-not (Test-Path -LiteralPath $ComposeFile -PathType Leaf)) {
  throw "Compose file was not found."
}

Write-Output "Rollback target: cyberinvestigator:$TargetVersion"
Write-Output "Required sequence:"
Write-Output "1. Enable maintenance mode."
Write-Output "2. Create and verify a storage backup."
Write-Output "3. Redeploy the immutable target image."
Write-Output "4. Run deployment and evidence-integrity verification."

if (-not $Apply) {
  Write-Output "Plan only. No deployment was changed. Re-run with -Apply after the maintenance and backup gates pass."
  return
}

$env:RELEASE_VERSION = $TargetVersion
docker compose -f $ComposeFile config --quiet
if ($LASTEXITCODE -ne 0) {
  throw "Compose configuration validation failed."
}
docker compose -f $ComposeFile up -d --no-build app
if ($LASTEXITCODE -ne 0) {
  throw "Rollback deployment failed."
}
Write-Output "Target image requested. Run scripts/verify-deployment.ps1 before ending maintenance mode."
