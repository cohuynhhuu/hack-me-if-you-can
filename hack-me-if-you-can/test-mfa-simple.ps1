#!/usr/bin/env pwsh
<#
.SYNOPSIS
    STEP 7: Quick MFA Testing Script
#>

param(
    [string]$BaseUrl = "http://localhost:5000/api/auth"
)

function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Info { Write-Host $args -ForegroundColor Cyan }
function Write-Fail { Write-Host $args -ForegroundColor Red }
function Write-Header { 
    Write-Host ""
    Write-Host ("="*70) -ForegroundColor Magenta
    Write-Host $args -ForegroundColor Magenta
    Write-Host ("="*70) -ForegroundColor Magenta
}

Write-Header "STEP 7: Multi-Factor Authentication Testing"

# Test 1: Register user
Write-Header "Test 1: Register User"
$testEmail = "mfatest2@test.com"
$testPassword = "Test123!"

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/register-secure" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
    } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
    
    Write-Success "✅ User registered: $testEmail"
    $userId = $result.userId
}
catch {
    if ($_.ErrorDetails.Message) {
        $error = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Info "User might exist: $($error.message)"
        
        # Try to get user ID by logging in
        try {
            $loginResult = Invoke-RestMethod -Uri "$BaseUrl/login-without-mfa" -Method Post -Body (@{
                email = $testEmail
                password = $testPassword
            } | ConvertTo-Json) -ContentType "application/json"
            
            $userId = $loginResult.userId
            Write-Info "Using existing user ID: $userId"
        }
        catch {
            Write-Fail "❌ Cannot proceed"
            exit 1
        }
    }
}

# Test 2: Enable MFA
Write-Header "Test 2: Enable MFA"
try {
    $mfaResult = Invoke-RestMethod -Uri "$BaseUrl/enable-mfa" -Method Post -Body (@{
        userId = $userId
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Success "✅ MFA setup initiated"
    $secret = $mfaResult.secret
    $qrCode = $mfaResult.qrCodeDataUrl
    
    Write-Info "`nSecret: $secret"
    Write-Info "QR Code: $($qrCode.Substring(0, 50))..."
    
    # Save QR code
    $htmlPath = "mfa-qrcode-simple.html"
    @"
<!DOCTYPE html>
<html>
<head>
    <title>MFA QR Code</title>
    <style>
        body { font-family: Arial; text-align: center; margin: 50px; }
        .secret { 
            background: #f0f0f0; 
            padding: 20px; 
            margin: 20px;
            font-size: 18px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <h1>🔐 Scan with Google Authenticator</h1>
    <img src="$qrCode" alt="QR Code" />
    <div class="secret">Secret: $secret</div>
    <p>Scan the QR code or enter the secret manually</p>
</body>
</html>
"@ | Out-File -FilePath $htmlPath -Encoding UTF8
    
    Write-Success "`n💾 QR code saved to: $htmlPath"
    Start-Process $htmlPath
    
    Write-Info "`n⏳ Please scan the QR code with Google Authenticator"
    Write-Info "Then press ENTER to continue..."
    Read-Host
}
catch {
    Write-Fail "❌ Failed to enable MFA: $($_.Exception.Message)"
    exit 1
}

# Test 3: Test invalid code
Write-Header "Test 3: Confirm MFA - Invalid Code"
try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/confirm-mfa" -Method Post -Body (@{
        userId = $userId
        code = "000000"
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Fail "❌ Invalid code was accepted (shouldn't happen!)"
}
catch {
    Write-Success "✅ Invalid code correctly rejected"
}

# Test 4: Get valid code and confirm
Write-Header "Test 4: Confirm MFA - Valid Code"
Write-Info "Please enter the 6-digit code from Google Authenticator:"
$code = Read-Host "Code"

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/confirm-mfa" -Method Post -Body (@{
        userId = $userId
        code = $code
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Success "✅ $($result.message)"
}
catch {
    Write-Fail "❌ MFA confirmation failed"
    Write-Info "Error: $($_.ErrorDetails.Message)"
    exit 1
}

# Test 5: Login WITHOUT MFA check (vulnerable)
Write-Header "Test 5: Login WITHOUT MFA Check (VULNERABLE)"
Write-Info "Simulating attacker with stolen password..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-without-mfa" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Fail "🚨 SECURITY BREACH!"
    Write-Fail "Attacker logged in with ONLY password (no MFA check)"
    Write-Info "Message: $($result.message)"
    Write-Info "Vulnerability: $($result.vulnerability)"
}
catch {
    Write-Info "Login blocked: $($_.ErrorDetails.Message)"
}

# Test 6: Login WITH MFA check - missing code
Write-Header "Test 6: Login WITH MFA - Missing Code"
try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-with-mfa" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
        mfaCode = ""
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Fail "❌ Login succeeded without MFA (shouldn't happen!)"
}
catch {
    $error = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Success "✅ Login blocked - MFA required"
    Write-Info "Message: $($error.message)"
}

# Test 7: Login WITH MFA check - invalid code
Write-Header "Test 7: Login WITH MFA - Invalid Code"
try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-with-mfa" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
        mfaCode = "999999"
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Fail "❌ Login succeeded with invalid code (shouldn't happen!)"
}
catch {
    Write-Success "✅ Login blocked - Invalid MFA code"
}

# Test 8: Login WITH MFA check - valid code
Write-Header "Test 8: Login WITH MFA - Valid Code"
Write-Info "Please enter current code from Google Authenticator:"
$validCode = Read-Host "Code"

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-with-mfa" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
        mfaCode = $validCode
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Success "✅ LOGIN SUCCESSFUL!"
    Write-Success "Message: $($result.message)"
    Write-Info "Token: $($result.token.Substring(0, 50))..."
}
catch {
    Write-Fail "❌ Login failed"
    Write-Info "Error: $($_.ErrorDetails.Message)"
}

# Test 9: Disable MFA
Write-Header "Test 9: Disable MFA"
try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/disable-mfa" -Method Post -Body (@{
        userId = $userId
        password = $testPassword
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Success "✅ MFA disabled"
    Write-Info "Message: $($result.message)"
}
catch {
    Write-Fail "❌ Failed to disable MFA"
}

# Summary
Write-Header "Summary"
Write-Success "`n✅ All MFA tests completed!`n"

Write-Info "Key Findings:"
Write-Info ""
Write-Fail "❌ VULNERABLE (login-without-mfa):"
Write-Fail "   Password alone = access granted"
Write-Fail "   Attacker with stolen password CAN log in"
Write-Info ""
Write-Success "✅ SECURE (login-with-mfa):"
Write-Success "   Password + MFA code = access granted"
Write-Success "   Attacker with stolen password CANNOT log in"
Write-Info ""
Write-Info "Real-World Impact:"
Write-Info "• 81% of breaches involve stolen passwords (Verizon)"
Write-Info "• MFA blocks 99.9% of automated attacks (Microsoft)"
Write-Info "• TOTP codes expire every 30 seconds"
Write-Info ""
Write-Success "🎉 MFA testing complete!"
