param(
    [Parameter(Mandatory = $true)]
    [string]$JobId
)

Invoke-RestMethod -Method Get -Uri "http://localhost:8080/jobs/$JobId"
