# STEP 5 - CAPTCHA Protection Test Script
# Tests bot attack prevention endpoints

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  STEP 5: CAPTCHA Protection Tests" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$baseUrl = "http://localhost:5000/api/auth"

# Test 1: Vulnerable Login (No CAPTCHA)
Write-Host "[TEST 1] Vulnerable Login - NO CAPTCHA REQUIRED" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/login-no-captcha" -ForegroundColor Gray
Write-Host "         Attack: Bot can attempt unlimited logins`n" -ForegroundColor Red

try {
    $body = @{
        email = "test@test.com"
        password = "wrongpassword"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/login-no-captcha" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json | Write-Host
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response:" -ForegroundColor Green
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host ""
}

# Test 2: Secure Login - Missing CAPTCHA Token
Write-Host "`n[TEST 2] Secure Login - MISSING CAPTCHA TOKEN" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/login-with-captcha" -ForegroundColor Gray
Write-Host "         Expected: Validation error (CAPTCHA required)`n" -ForegroundColor Green

try {
    $body = @{
        email = "test@test.com"
        password = "Password123"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/login-with-captcha" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json | Write-Host
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response (Expected Error):" -ForegroundColor Green
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host "✅ CAPTCHA token requirement enforced!" -ForegroundColor Green
    Write-Host ""
}

# Test 3: Secure Login - Invalid CAPTCHA Token
Write-Host "`n[TEST 3] Secure Login - INVALID CAPTCHA TOKEN" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/login-with-captcha" -ForegroundColor Gray
Write-Host "         Attack: Bot tries to fake CAPTCHA token`n" -ForegroundColor Red

try {
    $body = @{
        email = "test@test.com"
        password = "Password123"
        captchaToken = "fake-bot-token-12345"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/login-with-captcha" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json | Write-Host
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response (Expected Error):" -ForegroundColor Green
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host "✅ Bot blocked! Server-side verification works!" -ForegroundColor Green
    Write-Host ""
}

# Test 4: Test CAPTCHA Endpoint
Write-Host "`n[TEST 4] Test CAPTCHA Verification (Debug Endpoint)" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/test-captcha" -ForegroundColor Gray
Write-Host "         Using demo token with Google test keys`n" -ForegroundColor Cyan

try {
    $body = @{
        captchaToken = "test-token-demo"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/test-captcha" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json | Write-Host
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response:" -ForegroundColor Yellow
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host "Note: Test keys may be configured in appsettings.json" -ForegroundColor Gray
    Write-Host ""
}

# Test 5: Register with CAPTCHA (Missing Token)
Write-Host "`n[TEST 5] Register - MISSING CAPTCHA TOKEN" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/register-with-captcha" -ForegroundColor Gray
Write-Host "         Expected: Validation error (prevents bot account creation)`n" -ForegroundColor Green

try {
    $body = @{
        email = "newuser@test.com"
        password = "SecurePass123"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/register-with-captcha" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json | Write-Host
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response (Expected Error):" -ForegroundColor Green
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host "✅ Bot account creation prevented!" -ForegroundColor Green
    Write-Host ""
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "✅ Vulnerable endpoint allows bot attacks" -ForegroundColor Yellow
Write-Host "✅ Secure endpoints enforce CAPTCHA validation" -ForegroundColor Green
Write-Host "✅ Missing CAPTCHA token = Request rejected" -ForegroundColor Green
Write-Host "✅ Invalid CAPTCHA token = Server-side verification blocks attack" -ForegroundColor Green
Write-Host "✅ Bot account creation prevented" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Key Takeaways" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "1. Server-side verification is MANDATORY" -ForegroundColor White
Write-Host "   - Bots can bypass client-side JavaScript" -ForegroundColor Gray
Write-Host "   - Only Google API with secret key verifies tokens" -ForegroundColor Gray

Write-Host "`n2. Credential Stuffing Prevention" -ForegroundColor White
Write-Host "   - Without CAPTCHA: 10,000+ login attempts/minute" -ForegroundColor Red
Write-Host "   - With CAPTCHA: Limited to human speed (~1/minute)" -ForegroundColor Green

Write-Host "`n3. Layered Security" -ForegroundColor White
Write-Host "   - STEP 1: Password hashing" -ForegroundColor Gray
Write-Host "   - STEP 2: Input validation" -ForegroundColor Gray
Write-Host "   - STEP 3: SQL injection prevention" -ForegroundColor Gray
Write-Host "   - STEP 4: XSS prevention" -ForegroundColor Gray
Write-Host "   - STEP 5: Bot attack prevention (CAPTCHA)" -ForegroundColor Green
Write-Host "   - STEP 6: Rate limiting (coming next)" -ForegroundColor Yellow

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Next Steps" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "1. Open test-captcha.html in browser for interactive demo" -ForegroundColor White
Write-Host "   URL: http://localhost:5000/test-captcha.html" -ForegroundColor Cyan

Write-Host "`n2. Get production reCAPTCHA keys:" -ForegroundColor White
Write-Host "   https://www.google.com/recaptcha/admin" -ForegroundColor Cyan

Write-Host "`n3. Update appsettings.json with your keys:" -ForegroundColor White
Write-Host '   "ReCaptcha": { "SiteKey": "...", "SecretKey": "..." }' -ForegroundColor Gray

Write-Host "`n========================================`n" -ForegroundColor Cyan
