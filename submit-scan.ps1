param(
    [Parameter(Mandatory = $true)]
    [string]$Url
)

$body = @{
    url = $Url
    run_external_tools = $true
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/scan" -ContentType "application/json" -Body $body
