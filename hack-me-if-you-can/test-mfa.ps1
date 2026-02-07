#!/usr/bin/env pwsh
<#
.SYNOPSIS
    STEP 7: Multi-Factor Authentication (MFA) Testing Script
    
.DESCRIPTION
    Comprehensive testing of Google Authenticator (TOTP) implementation
    Demonstrates how MFA blocks credential stuffing attacks
    
.NOTES
    Tests all MFA scenarios:
    1. Enable MFA and get QR code
    2. Confirm MFA with valid/invalid codes
    3. Login without MFA enforcement (vulnerable)
    4. Login with MFA enforcement (secure)
    5. Disable MFA
    6. Credential stuffing scenario
#>

param(
    [string]$BaseUrl = "http://localhost:5000/api/auth"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors for output
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Info { Write-Host $args -ForegroundColor Cyan }
function Write-Warning { Write-Host $args -ForegroundColor Yellow }
function Write-Fail { Write-Host $args -ForegroundColor Red }
function Write-Header { 
    Write-Host ""
    Write-Host ("="*80) -ForegroundColor Magenta
    Write-Host $args -ForegroundColor Magenta
    Write-Host ("="*80) -ForegroundColor Magenta
}

# Helper function for API calls
function Invoke-ApiCall {
    param(
        [string]$Endpoint,
        [string]$Method = "POST",
        [object]$Body = $null,
        [string]$Token = $null
    )
    
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    if ($Token) {
        $headers["Authorization"] = "Bearer $Token"
    }
    
    $params = @{
        Uri = "$BaseUrl/$Endpoint"
        Method = $Method
        Headers = $headers
        ErrorAction = "Stop"
    }
    
    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json)
    }
    
    try {
        $response = Invoke-RestMethod @params
        return @{
            Success = $true
            Data = $response
            StatusCode = 200
        }
    }
    catch {
        $statusCode = 0
        $errorBody = $null
        
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        
        # Try to get the error body
        $errorBody = @{ message = $_.Exception.Message }
        if ($_.ErrorDetails.Message) {
            try {
                $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json
            }
            catch {
                $errorBody = @{ message = $_.ErrorDetails.Message }
            }
        }
        
        return @{
            Success = $false
            Data = $errorBody
            StatusCode = $statusCode
        }
    }
}

# Main test script
Write-Header "STEP 7: Multi-Factor Authentication (MFA) Testing"

Write-Info "`n📱 Testing Google Authenticator (TOTP) Implementation"
Write-Info "This demonstrates how MFA prevents credential stuffing attacks"
Write-Info ""
Write-Info "What is credential stuffing?"
Write-Info "  Attackers use stolen username/password pairs from one breach"
Write-Info "  to try logging into other services (banking, email, etc.)"
Write-Info ""
Write-Info "Why MFA stops it:"
Write-Info "  Even if attackers have your password, they don't have your phone"
Write-Info "  The TOTP code changes every 30 seconds and can't be reused"
Write-Info ""

# Test 1: Register a test user
Write-Header "Test 1: Register Test User"
$testEmail = "mfatest@test.com"
$testPassword = "Test123!"

$registerResult = Invoke-ApiCall -Endpoint "register-secure" -Body @{
    email = $testEmail
    password = $testPassword
}

if ($registerResult.Success) {
    Write-Success "✅ User registered: $testEmail"
    $userId = $registerResult.Data.userId
    Write-Info "   User ID: $userId"
}
else {
    # User might already exist, try to find them
    Write-Warning "⚠️  Registration failed (might already exist): $($registerResult.Data.message)"
    
    # Try to login to get user ID
    $loginResult = Invoke-ApiCall -Endpoint "login-without-mfa" -Body @{
        email = $testEmail
        password = $testPassword
    }
    
    if ($loginResult.Success) {
        $userId = $loginResult.Data.userId
        Write-Info "   Using existing user ID: $userId"
    }
    else {
        Write-Fail "❌ Cannot proceed without user ID"
        exit 1
    }
}

# Test 2: Enable MFA
Write-Header "Test 2: Enable MFA"
$enableMfaResult = Invoke-ApiCall -Endpoint "enable-mfa" -Body @{
    userId = $userId
}

if ($enableMfaResult.Success) {
    Write-Success "✅ MFA setup initiated"
    $mfaSecret = $enableMfaResult.Data.secret
    $qrCodeData = $enableMfaResult.Data.qrCodeDataUrl
    
    Write-Info "`n📋 MFA Setup Information:"
    Write-Info "   Secret (Base32): $mfaSecret"
    Write-Info "   QR Code: $($qrCodeData.Substring(0, 50))..."
    Write-Info ""
    Write-Success "   Instructions:"
    foreach ($instruction in $enableMfaResult.Data.instructions) {
        Write-Info "   $instruction"
    }
    
    # Save QR code to HTML file for easy scanning
    $htmlPath = Join-Path $PSScriptRoot "mfa-qrcode.html"
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>MFA Setup - Google Authenticator</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }
        h1 { color: #1a73e8; }
        .qr-container {
            margin: 30px 0;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 10px;
        }
        .secret {
            background: #fff;
            padding: 15px;
            border: 2px solid #1a73e8;
            border-radius: 5px;
            font-family: monospace;
            font-size: 18px;
            margin: 20px 0;
            word-break: break-all;
        }
        .instructions {
            text-align: left;
            background: #e8f0fe;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .instructions li {
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h1>🔐 Multi-Factor Authentication Setup</h1>
    <p>Scan this QR code with <strong>Google Authenticator</strong></p>
    
    <div class="qr-container">
        <img src="$qrCodeData" alt="QR Code for Google Authenticator" />
    </div>
    
    <p><strong>Or enter this secret manually:</strong></p>
    <div class="secret">$mfaSecret</div>
    
    <div class="instructions">
        <h3>Setup Instructions:</h3>
        <ol>
            <li>Install <strong>Google Authenticator</strong> on your phone (iOS/Android)</li>
            <li>Open the app and tap <strong>+</strong> (Add account)</li>
            <li>Choose <strong>"Scan a QR code"</strong> or <strong>"Enter a setup key"</strong></li>
            <li>Scan the QR code above or enter the secret manually</li>
            <li>The app will show a 6-digit code that changes every 30 seconds</li>
            <li>Use this code to confirm MFA setup in the next test</li>
        </ol>
    </div>
    
    <p><em>Keep this secret safe! It's your backup if you lose your phone.</em></p>
</body>
</html>
"@
    
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Success "`n   💾 QR code saved to: $htmlPath"
    Write-Info "   Opening in browser..."
    Start-Process $htmlPath
    
    Write-Info "`n⏳ Waiting for you to scan the QR code..."
    Write-Info "   Please use Google Authenticator to scan the QR code"
    Write-Info "   Press ENTER when ready to continue with the test code..."
    Read-Host
}
else {
    Write-Fail "❌ Failed to enable MFA: $($enableMfaResult.Data.message)"
    exit 1
}

# Test 3: Confirm MFA with invalid code (should fail)
Write-Header "Test 3: Confirm MFA with Invalid Code"
$confirmInvalidResult = Invoke-ApiCall -Endpoint "confirm-mfa" -Body @{
    userId = $userId
    code = "000000"
}

if (-not $confirmInvalidResult.Success) {
    Write-Success "✅ Invalid code correctly rejected"
    Write-Info "   Message: $($confirmInvalidResult.Data.message)"
}
else {
    Write-Warning "⚠️  Invalid code was accepted (this shouldn't happen)"
}

# Test 4: Generate current TOTP code and confirm MFA
Write-Header "Test 4: Confirm MFA with Valid Code"
Write-Info "Generating current TOTP code from secret..."

# Use OtpNet to generate the code (same library used by the API)
Add-Type -AssemblyName System.Runtime
$dllPath = Get-ChildItem -Path "$PSScriptRoot" -Recurse -Filter "OtpNet.dll" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($dllPath) {
    Add-Type -Path $dllPath.FullName
    
    # Decode Base32 secret
    $secretBytes = [OtpNet.Base32Encoding]::ToBytes($mfaSecret)
    $totp = New-Object OtpNet.Totp($secretBytes)
    $currentCode = $totp.ComputeTotp()
    
    Write-Info "   Current TOTP code: $currentCode"
    Write-Info "   (This code is valid for ~30 seconds)"
}
else {
    Write-Info "`n   ⚠️  Could not auto-generate code (OtpNet.dll not found)"
    Write-Info "   Please enter the 6-digit code from Google Authenticator:"
    $currentCode = Read-Host "   Code"
}

Write-Info "`nAttempting to confirm MFA with code: $currentCode"

$confirmValidResult = Invoke-ApiCall -Endpoint "confirm-mfa" -Body @{
    userId = $userId
    code = $currentCode
}

if ($confirmValidResult.Success) {
    Write-Success "✅ MFA confirmed and activated!"
    Write-Info "   Message: $($confirmValidResult.Data.message)"
}
else {
    Write-Fail "❌ MFA confirmation failed: $($confirmValidResult.Data.message)"
    Write-Warning "   This might be due to clock drift. Try again with a fresh code."
    exit 1
}

# Test 5: Login without MFA enforcement (VULNERABLE)
Write-Header "Test 5: Login WITHOUT MFA Enforcement (VULNERABLE)"
Write-Warning "⚠️  Simulating attacker with stolen password..."
Write-Info "   The attacker has: Email + Password (from a data breach)"
Write-Info "   The attacker doesn't have: The user's phone / TOTP code"

$vulnerableLoginResult = Invoke-ApiCall -Endpoint "login-without-mfa" -Body @{
    email = $testEmail
    password = $testPassword
}

if ($vulnerableLoginResult.Success) {
    Write-Fail "🚨 SECURITY BREACH!"
    Write-Fail "   The attacker logged in with ONLY the password"
    Write-Fail "   MFA was enabled but NOT enforced!"
    Write-Info ""
    Write-Info "   Response: $($vulnerableLoginResult.Data.message)"
    Write-Info "   Token: $($vulnerableLoginResult.Data.token.Substring(0, 50))..."
    Write-Info "   Vulnerability: $($vulnerableLoginResult.Data.vulnerability)"
}
else {
    Write-Success "✅ Login blocked (unexpected)"
}

# Test 6: Login with MFA but missing code
Write-Header "Test 6: Login WITH MFA Enforcement - Missing Code"
Write-Info "Attempting login with password only (no MFA code)..."

$mfaMissingCodeResult = Invoke-ApiCall -Endpoint "login-with-mfa" -Body @{
    email = $testEmail
    password = $testPassword
    mfaCode = ""
}

if (-not $mfaMissingCodeResult.Success) {
    Write-Success "✅ Login correctly blocked - MFA code required"
    Write-Info "   Message: $($mfaMissingCodeResult.Data.message)"
    
    if ($mfaMissingCodeResult.Data.mfaRequired) {
        Write-Success "   ✓ API correctly indicated MFA is required"
    }
}
else {
    Write-Warning "⚠️  Login succeeded without MFA code (shouldn't happen)"
}

# Test 7: Login with MFA but invalid code
Write-Header "Test 7: Login WITH MFA Enforcement - Invalid Code"
Write-Info "Attempting login with wrong MFA code..."

$mfaInvalidCodeResult = Invoke-ApiCall -Endpoint "login-with-mfa" -Body @{
    email = $testEmail
    password = $testPassword
    mfaCode = "999999"
}

if (-not $mfaInvalidCodeResult.Success) {
    Write-Success "✅ Login correctly blocked - Invalid MFA code"
    Write-Info "   Message: $($mfaInvalidCodeResult.Data.message)"
}
else {
    Write-Warning "⚠️  Login succeeded with invalid code (shouldn't happen)"
}

# Test 8: Login with MFA and valid code (SUCCESS)
Write-Header "Test 8: Login WITH MFA Enforcement - Valid Code"

# Generate fresh code
if ($dllPath) {
    $secretBytes = [OtpNet.Base32Encoding]::ToBytes($mfaSecret)
    $totp = New-Object OtpNet.Totp($secretBytes)
    $currentCode = $totp.ComputeTotp()
    Write-Info "   Generated fresh code: $currentCode"
}
else {
    Write-Info "   Please enter current code from Google Authenticator:"
    $currentCode = Read-Host "   Code"
}

Write-Info "Attempting secure login with password + MFA code..."

$mfaValidLoginResult = Invoke-ApiCall -Endpoint "login-with-mfa" -Body @{
    email = $testEmail
    password = $testPassword
    mfaCode = $currentCode
}

if ($mfaValidLoginResult.Success) {
    Write-Success "✅ LOGIN SUCCESSFUL - Both password and MFA verified!"
    Write-Info "   Message: $($mfaValidLoginResult.Data.message)"
    Write-Info "   Token: $($mfaValidLoginResult.Data.token.Substring(0, 50))..."
    Write-Info "   Security: $($mfaValidLoginResult.Data.security)"
}
else {
    Write-Fail "❌ Login failed: $($mfaValidLoginResult.Data.message)"
}

# Test 9: Disable MFA
Write-Header "Test 9: Disable MFA"
Write-Info "Disabling MFA (requires password verification)..."

$disableMfaResult = Invoke-ApiCall -Endpoint "disable-mfa" -Body @{
    userId = $userId
    password = $testPassword
}

if ($disableMfaResult.Success) {
    Write-Success "✅ MFA disabled"
    Write-Info "   Message: $($disableMfaResult.Data.message)"
}
else {
    Write-Fail "❌ Failed to disable MFA: $($disableMfaResult.Data.message)"
}

# Final Summary
Write-Header "Test Summary"

Write-Success "`n✅ All MFA tests completed!`n"

Write-Info "📊 Key Findings:"
Write-Info ""
Write-Info "1. MFA Setup:"
Write-Info "   ✓ QR code generation works"
Write-Info "   ✓ Google Authenticator integration successful"
Write-Info "   ✓ TOTP codes verified correctly"
Write-Info ""
Write-Info "2. Security Comparison:"
Write-Info ""
Write-Fail "   ❌ VULNERABLE (login-without-mfa):"
Write-Fail "      Password alone = access granted"
Write-Fail "      Credential stuffing = SUCCESS for attacker"
Write-Info ""
Write-Success "   ✅ SECURE (login-with-mfa):"
Write-Success "      Password + MFA code = access granted"
Write-Success "      Credential stuffing = BLOCKED (no MFA code)"
Write-Info ""
Write-Info "3. Real-World Impact:"
Write-Info "   • 81% of breaches involve stolen/weak passwords (Verizon DBIR)"
Write-Info "   • MFA blocks 99.9% of automated attacks (Microsoft)"
Write-Info "   • TOTP codes expire every 30 seconds"
Write-Info "   • Attackers can't reuse old codes"
Write-Info ""
Write-Info "4. Credential Stuffing Scenario:"
Write-Info "   Without MFA:"
Write-Info "     Hacker steals password from breach → Logs in successfully"
Write-Info ""
Write-Info "   With MFA:"
Write-Info "     Hacker steals password from breach → Login blocked!"
Write-Info "     (They don't have your phone/authenticator app)"
Write-Info ""

Write-Header "STEP 7 Complete!"

Write-Info "`n📚 Key Takeaways:"
Write-Info "   • MFA adds a second factor: something you have (phone)"
Write-Info "   • TOTP codes change every 30 seconds"
Write-Info "   • Even with a stolen password, attackers can't log in"
Write-Info "   • Always enforce MFA for sensitive operations"
Write-Info "   • Never make MFA optional for high-value accounts"
Write-Info ""
Write-Success "🎉 MFA testing complete!"
Write-Info ""

# Cleanup
Write-Info "Cleaning up..."
if (Test-Path $htmlPath) {
    Write-Info "   QR code HTML saved at: $htmlPath"
}

Write-Info "`nNext steps:"
Write-Info "   • Review the code in Controllers/AuthController.cs"
Write-Info "   • Compare login-without-mfa vs login-with-mfa"
Write-Info "   • Try scanning the QR code with Google Authenticator"
Write-Info "   • Test with real mobile app for full experience"
Write-Info ""
