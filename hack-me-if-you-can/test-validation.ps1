# STEP 2 - Form Validation Testing Script

$baseUrl = "http://localhost:5000/api/auth"

Write-Host "`n🧪 Testing STEP 2: Form Validation" -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan

# Test 1: Valid registration
Write-Host "✅ Test 1: Valid Registration" -ForegroundColor Green
$body = @{
    email = "valid@example.com"
    password = "SecurePass123"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "$baseUrl/register-secure" `
    -ContentType "application/json" -Body $body | ConvertTo-Json
Write-Host ""

# Test 2: Missing required fields
Write-Host "❌ Test 2: Missing Required Fields" -ForegroundColor Red
$body = @{
    email = ""
    password = ""
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/register-secure" `
        -ContentType "application/json" -Body $body | ConvertTo-Json
} catch {
    $_.Exception.Response | ConvertTo-Json
}
Write-Host ""

# Test 3: Invalid email format
Write-Host "❌ Test 3: Invalid Email Format" -ForegroundColor Red
$body = @{
    email = "not-an-email"
    password = "SecurePass123"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/register-secure" `
        -ContentType "application/json" -Body $body | ConvertTo-Json
} catch {
    Write-Host "Validation failed (expected)" -ForegroundColor Yellow
}
Write-Host ""

# Test 4: Password too short
Write-Host "❌ Test 4: Password Too Short" -ForegroundColor Red
$body = @{
    email = "short@example.com"
    password = "short"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/register-secure" `
        -ContentType "application/json" -Body $body | ConvertTo-Json
} catch {
    Write-Host "Validation failed (expected)" -ForegroundColor Yellow
}
Write-Host ""

# Test 5: Duplicate email
Write-Host "❌ Test 5: Duplicate Email" -ForegroundColor Red
$body = @{
    email = "valid@example.com"
    password = "AnotherPass456"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/register-secure" `
        -ContentType "application/json" -Body $body | ConvertTo-Json
} catch {
    Write-Host "Email already registered (expected)" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "✅ Validation tests complete!" -ForegroundColor Green
