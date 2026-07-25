param(
  [string]$BaseUrl = "http://127.0.0.1:8000",
  [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"
$base = $BaseUrl.TrimEnd("/")
$checks = @(
  @{ Name = "Liveness"; Uri = "$base/api/v1/health/live" },
  @{ Name = "Readiness"; Uri = "$base/api/v1/health/ready" }
)

foreach ($check in $checks) {
  try {
    $response = Invoke-WebRequest -Uri $check.Uri -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing
    if ($response.StatusCode -ne 200) {
      throw "HTTP $($response.StatusCode)"
    }
    $payload = $response.Content | ConvertFrom-Json
    if ($payload.status -notin @("ok", "operational")) {
      throw "Reported status '$($payload.status)'"
    }
    Write-Output "$($check.Name): passed"
  }
  catch {
    Write-Error "$($check.Name): failed - $($_.Exception.Message)"
    exit 1
  }
}

Write-Output "Deployment verification passed for $base."
