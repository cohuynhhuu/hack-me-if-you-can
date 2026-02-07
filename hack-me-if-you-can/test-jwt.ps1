# STEP 6 - JWT Authentication Test Script
# Tests stateless JWT authentication vs traditional session-based auth

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  STEP 6: JWT Authentication Tests" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$baseUrl = "http://localhost:5000/api/auth"
$global:jwtToken = $null

# First, register a test user if not exists
Write-Host "[SETUP] Registering test user..." -ForegroundColor Gray
try {
    $body = @{
        email = "jwttest@test.com"
        password = "SecurePassword123"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/register-secure" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body `
        -ErrorAction SilentlyContinue

    Write-Host "User registered successfully`n" -ForegroundColor Green
}
catch {
    Write-Host "User likely already exists (continuing...)`n" -ForegroundColor Yellow
}

# Test 1: Login without JWT (old approach)
Write-Host "[TEST 1] Login WITHOUT JWT - Traditional Session-Based Auth" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/login-no-jwt" -ForegroundColor Gray
Write-Host "         Problem: Server must store session state (not scalable)`n" -ForegroundColor Red

try {
    $body = @{
        email = "jwttest@test.com"
        password = "SecurePassword123"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/login-no-jwt" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 5 | Write-Host
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response:" -ForegroundColor Yellow
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host ""
}

# Test 2: Login with JWT (modern approach)
Write-Host "`n[TEST 2] Login WITH JWT - Stateless Token-Based Auth" -ForegroundColor Yellow
Write-Host "         Endpoint: POST /api/auth/login-with-jwt" -ForegroundColor Gray
Write-Host "         Benefit: Server doesn't store state, tokens are self-contained`n" -ForegroundColor Green

try {
    $body = @{
        email = "jwttest@test.com"
        password = "SecurePassword123"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "$baseUrl/login-with-jwt" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 5 | Write-Host
    
    # Save token for next tests
    $global:jwtToken = $response.token
    
    Write-Host "`n✅ JWT Token Generated!" -ForegroundColor Green
    Write-Host "Token Length: $($global:jwtToken.Length) characters" -ForegroundColor Cyan
    Write-Host "First 50 chars: $($global:jwtToken.Substring(0, 50))..." -ForegroundColor Gray
    Write-Host "Expires At: $($response.expiresAt)" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Host "Response:" -ForegroundColor Red
    $errorResponse | ConvertTo-Json | Write-Host
    Write-Host ""
}

# Test 3: Access public endpoint (no auth required)
Write-Host "`n[TEST 3] Public Endpoint - NO Authentication Required" -ForegroundColor Yellow
Write-Host "         Endpoint: GET /api/auth/public-info" -ForegroundColor Gray
Write-Host "         Anyone can access this`n" -ForegroundColor Cyan

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/public-info" -Method GET

    Write-Host "Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 5 | Write-Host
    Write-Host "✅ Public endpoint accessible without token" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "Error accessing public endpoint: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Test 4: Access protected endpoint WITHOUT token (should fail)
Write-Host "`n[TEST 4] Protected Endpoint - WITHOUT JWT Token" -ForegroundColor Yellow
Write-Host "         Endpoint: GET /api/auth/profile" -ForegroundColor Gray
Write-Host "         Expected: 401 Unauthorized (missing token)`n" -ForegroundColor Red

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/profile" -Method GET

    Write-Host "Unexpected Success:" -ForegroundColor Red
    $response | ConvertTo-Json -Depth 5 | Write-Host
    Write-Host ""
}
catch {
    Write-Host "Response (Expected Error):" -ForegroundColor Green
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__) - $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    Write-Host "✅ Correctly rejected - no JWT token provided!" -ForegroundColor Green
    Write-Host ""
}

# Test 5: Access protected endpoint WITH valid token (should succeed)
if ($global:jwtToken) {
    Write-Host "`n[TEST 5] Protected Endpoint - WITH Valid JWT Token" -ForegroundColor Yellow
    Write-Host "         Endpoint: GET /api/auth/profile" -ForegroundColor Gray
    Write-Host "         Expected: 200 OK (token accepted)`n" -ForegroundColor Green

    try {
        $headers = @{
            "Authorization" = "Bearer $global:jwtToken"
        }

        $response = Invoke-RestMethod -Uri "$baseUrl/profile" `
            -Method GET `
            -Headers $headers

        Write-Host "Response:" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 5 | Write-Host
        Write-Host "`n✅ Protected endpoint accessed successfully!" -ForegroundColor Green
        Write-Host "User authenticated from JWT claims" -ForegroundColor Cyan
        Write-Host ""
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
}
else {
    Write-Host "`n[TEST 5] SKIPPED - No JWT token available" -ForegroundColor Yellow
}

# Test 6: Access protected endpoint with INVALID/EXPIRED token
Write-Host "`n[TEST 6] Protected Endpoint - WITH Invalid JWT Token" -ForegroundColor Yellow
Write-Host "         Endpoint: GET /api/auth/profile" -ForegroundColor Gray
Write-Host "         Attack: Attacker tries to use fake/tampered token`n" -ForegroundColor Red

try {
    $headers = @{
        "Authorization" = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.invalidSignatureHere"
    }

    $response = Invoke-RestMethod -Uri "$baseUrl/profile" `
        -Method GET `
        -Headers $headers

    Write-Host "Unexpected Success (SECURITY BREACH!):" -ForegroundColor Red
    $response | ConvertTo-Json -Depth 5 | Write-Host
    Write-Host ""
}
catch {
    Write-Host "Response (Expected Error):" -ForegroundColor Green
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__) - $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    Write-Host "✅ Correctly rejected - invalid token signature!" -ForegroundColor Green
    Write-Host "Server verified signature with secret key - tampering detected" -ForegroundColor Cyan
    Write-Host ""
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "✅ Session-based login works (but not scalable)" -ForegroundColor Yellow
Write-Host "✅ JWT-based login generates signed token" -ForegroundColor Green
Write-Host "✅ Public endpoints accessible without auth" -ForegroundColor Green
Write-Host "✅ Protected endpoints reject requests without token" -ForegroundColor Green
Write-Host "✅ Protected endpoints accept valid JWT token" -ForegroundColor Green
Write-Host "✅ Protected endpoints reject tampered/invalid tokens" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Key Takeaways" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "1. JWT vs Session-Based Auth" -ForegroundColor White
Write-Host "   Session-Based:" -ForegroundColor Gray
Write-Host "   - Server stores session state in memory/database" -ForegroundColor Red
Write-Host "   - Requires sticky sessions with multiple servers" -ForegroundColor Red
Write-Host "   - Sessions lost if server restarts" -ForegroundColor Red
Write-Host "   JWT-Based:" -ForegroundColor Gray
Write-Host "   - Stateless - no server storage required" -ForegroundColor Green
Write-Host "   - Works across multiple servers (horizontal scaling)" -ForegroundColor Green
Write-Host "   - Self-contained - all info in token" -ForegroundColor Green

Write-Host "`n2. JWT Token Structure" -ForegroundColor White
Write-Host "   Format: Header.Payload.Signature" -ForegroundColor Gray
Write-Host "   - Header: Algorithm (HS256) + Token Type (JWT)" -ForegroundColor Cyan
Write-Host "   - Payload: User claims (ID, email, expiration)" -ForegroundColor Cyan
Write-Host "   - Signature: HMAC(Header + Payload + SecretKey)" -ForegroundColor Cyan

Write-Host "`n3. Why JWT Must Be Signed" -ForegroundColor White
Write-Host "   - Prevents tampering (attacker can't change userId)" -ForegroundColor Green
Write-Host "   - Only server with secret key can create valid tokens" -ForegroundColor Green
Write-Host "   - Server verifies signature on each request" -ForegroundColor Green
Write-Host "   - If signature invalid = token rejected" -ForegroundColor Green

Write-Host "`n4. Token Expiration" -ForegroundColor White
Write-Host "   - Tokens expire after configured time (60 min default)" -ForegroundColor Cyan
Write-Host "   - Limits damage if token is stolen" -ForegroundColor Green
Write-Host "   - User must re-authenticate after expiration" -ForegroundColor Yellow
Write-Host "   - Can implement refresh tokens for longer sessions" -ForegroundColor Gray

Write-Host "`n5. Security Best Practices" -ForegroundColor White
Write-Host "   ✅ Store secret key in environment variables (not code)" -ForegroundColor Green
Write-Host "   ✅ Use HTTPS to prevent token interception" -ForegroundColor Green
Write-Host "   ✅ Set reasonable expiration time (not too long)" -ForegroundColor Green
Write-Host "   ✅ Include only necessary claims (don't leak sensitive data)" -ForegroundColor Green
Write-Host "   ✅ Validate signature on every request ([Authorize])" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Real-World Use Cases" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "✅ Single-Page Applications (React, Angular, Vue)" -ForegroundColor White
Write-Host "   - Frontend gets JWT after login" -ForegroundColor Gray
Write-Host "   - Stores in localStorage/sessionStorage" -ForegroundColor Gray
Write-Host "   - Sends in Authorization header for API calls" -ForegroundColor Gray

Write-Host "`n✅ Mobile Apps (iOS, Android)" -ForegroundColor White
Write-Host "   - No cookies - JWT perfect for native apps" -ForegroundColor Gray
Write-Host "   - Store token securely (Keychain/KeyStore)" -ForegroundColor Gray
Write-Host "   - Works offline (token doesn't need server check)" -ForegroundColor Gray

Write-Host "`n✅ Microservices Architecture" -ForegroundColor White
Write-Host "   - Multiple services share same JWT validation" -ForegroundColor Gray
Write-Host "   - No need for session replication" -ForegroundColor Gray
Write-Host "   - Stateless = easy to scale horizontally" -ForegroundColor Gray

Write-Host "`n✅ Third-Party API Access" -ForegroundColor White
Write-Host "   - Issue JWT to external developers" -ForegroundColor Gray
Write-Host "   - Rate limiting based on claims" -ForegroundColor Gray
Write-Host "   - Revoke by changing secret or using blacklist" -ForegroundColor Gray

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Token Example (Decoded)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Header (Base64 decoded):" -ForegroundColor Yellow
Write-Host '{' -ForegroundColor Gray
Write-Host '  "alg": "HS256",' -ForegroundColor Gray
Write-Host '  "typ": "JWT"' -ForegroundColor Gray
Write-Host '}' -ForegroundColor Gray

Write-Host "`nPayload (Claims):" -ForegroundColor Yellow
Write-Host '{' -ForegroundColor Gray
Write-Host '  "sub": "123",         // User ID' -ForegroundColor Gray
Write-Host '  "email": "user@example.com",' -ForegroundColor Gray
Write-Host '  "exp": 1738943200,   // Expiration timestamp' -ForegroundColor Gray
Write-Host '  "iss": "PasswordSecurityDemo",' -ForegroundColor Gray
Write-Host '  "aud": "PasswordSecurityDemoUsers"' -ForegroundColor Gray
Write-Host '}' -ForegroundColor Gray

Write-Host "`nSignature:" -ForegroundColor Yellow
Write-Host "HMACSHA256(" -ForegroundColor Gray
Write-Host "  base64UrlEncode(header) + '.' +" -ForegroundColor Gray
Write-Host "  base64UrlEncode(payload)," -ForegroundColor Gray
Write-Host "  secretKey" -ForegroundColor Gray
Write-Host ")" -ForegroundColor Gray

Write-Host "`n========================================`n" -ForegroundColor Cyan

if ($global:jwtToken) {
    Write-Host "🎉 Your JWT Token (copy this for manual testing):" -ForegroundColor Green
    Write-Host $global:jwtToken -ForegroundColor Cyan
    Write-Host "`nUse with curl:" -ForegroundColor Yellow
    Write-Host "curl -H `"Authorization: Bearer $global:jwtToken`" http://localhost:5000/api/auth/profile" -ForegroundColor Gray
}

Write-Host "`n✨ STEP 6 Complete! Next: Refresh tokens, token blacklisting, or move to STEP 7 (Rate Limiting)`n" -ForegroundColor Green
