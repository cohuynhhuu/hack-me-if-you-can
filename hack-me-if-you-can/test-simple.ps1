# Simple SQL Injection Test
Write-Host "=== Testing SQL Injection Demo ===" -ForegroundColor Cyan

$baseUrl = "http://localhost:5000/api/auth"

# First, register a test user
Write-Host "`nRegistering test user..." -ForegroundColor Yellow
$registerData = @{
    email = "victim@test.com"
    password = "Password123"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/register-secure" -Method Post `
        -ContentType "application/json" -Body $registerData
    Write-Host "✓ User registered successfully" -ForegroundColor Green
} catch {
    Write-Host "User may already exist (that's OK)" -ForegroundColor Gray
}

# Attack 1: SQL Injection on vulnerable login
Write-Host "`n=== ATTACK 1: SQL Injection on /login-vulnerable ===" -ForegroundColor Red
Write-Host "Payload: email=victim@test.com'-- (comment injection)" -ForegroundColor Yellow

$attackEmail = [System.Web.HttpUtility]::UrlEncode("victim@test.com'--")
$attackPassword = [System.Web.HttpUtility]::UrlEncode("wrong")

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/login-vulnerable?email=$attackEmail&password=$attackPassword" -Method Post
    Write-Host "🚨 BREACH SUCCESSFUL! Login bypassed without valid password" -ForegroundColor Red
    Write-Host "Response: $($response | ConvertTo-Json)" -ForegroundColor Red
} catch {
    Write-Host "Attack failed or endpoint error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Attack 2: Test the secure version
Write-Host "`n=== DEFENSE: Testing /login-secure ===" -ForegroundColor Green
Write-Host "Same payload on secure endpoint..." -ForegroundColor Yellow

$attackData = @{
    email = "victim@test.com'--"
    password = "wrong"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/login-secure" -Method Post `
        -ContentType "application/json" -Body $attackData
    Write-Host "⚠ Unexpected: Attack worked on secure endpoint!" -ForegroundColor Red
} catch {
    Write-Host "✓ PROTECTED! Attack blocked. Error: $($_.Exception.Message)" -ForegroundColor Green
}

# Attack 3: OR 1=1 attack
Write-Host "`n=== ATTACK 2: OR 1=1 on /login-vulnerable ===" -ForegroundColor Red
Write-Host "Payload: email=' OR 1=1 -- (always true condition)" -ForegroundColor Yellow

$orEmail = [System.Web.HttpUtility]::UrlEncode("' OR 1=1 --")
$orPassword = [System.Web.HttpUtility]::UrlEncode("anything")

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/login-vulnerable?email=$orEmail&password=$orPassword" -Method Post
    Write-Host "🚨 MASSIVE BREACH! Database compromised" -ForegroundColor Red
    Write-Host "Response: $($response | ConvertTo-Json)" -ForegroundColor Red
} catch {
    Write-Host "Attack failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
