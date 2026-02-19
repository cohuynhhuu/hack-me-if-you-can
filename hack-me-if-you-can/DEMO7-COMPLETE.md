# DEMO 7: Multi-Factor Authentication (MFA) - COMPLETE ✅

## Overview

Successfully implemented **Google Authenticator integration** using **TOTP (Time-based One-Time Password)** to demonstrate how **multi-factor authentication blocks credential stuffing attacks** even when attackers have stolen passwords.

---

## What is Multi-Factor Authentication (MFA)?

MFA requires users to provide **two or more verification factors** to gain access:

1. **Something you know** → Password
2. **Something you have** → Phone with authenticator app
3. **Something you are** → Biometric (fingerprint, face)

This implementation uses factors #1 and #2 (password + TOTP code from Google Authenticator).

---

## What is TOTP?

**TOTP (Time-based One-Time Password)** is defined in [RFC 6238](https://tools.ietf.org/html/rfc6238):

- Generates a **6-digit code** that changes every **30 seconds**
- Based on:
  - **Shared secret** (stored on server and in authenticator app)
  - **Current time** (Unix timestamp divided by 30-second time step)
  - **HMAC-SHA1 algorithm** (cryptographic hash)

### How TOTP Works

```
Current Time = 1675800000 seconds since Unix epoch
Time Step = 30 seconds
Counter = 1675800000 / 30 = 55860000

TOTP Code = HMAC-SHA1(Secret, Counter) → 6-digit code
```

The code changes every 30 seconds, so attackers can't reuse old codes.

---

## What is Credential Stuffing?

**Credential stuffing** is a cyberattack where hackers use **stolen username/password pairs** from one breach to try logging into OTHER services.

### How It Works

1. Hacker steals 10 million passwords from Company A (e.g., a forum breach)
2. Hacker tries those same email/password combos on:
   - Banks
   - Email providers
   - Social media
   - E-commerce sites
   - Cloud services

3. **Many users reuse the same password everywhere**, so hackers get access!

### Real-World Statistics

- **81% of data breaches** involve stolen or weak passwords (Verizon DBIR 2022)
- **59% of people** reuse passwords across multiple sites (Google survey)
- **Credential stuffing accounts for 90%+** of all login attempts on some websites

---

## How MFA Blocks Credential Stuffing

### Without MFA (VULNERABLE)

```
Attacker has: Email + Password (from a breach)
Login attempt: POST /login-without-mfa
Server checks: Password matches? ✅
Result: ✅ ACCESS GRANTED ← 🚨 SECURITY BREACH!
```

### With MFA (SECURE)

```
Attacker has: Email + Password (from a breach)
Attacker missing: User's phone / TOTP code

Login attempt: POST /login-with-mfa
Server checks: 
  1. Password matches? ✅
  2. TOTP code matches? ❌ (attacker doesn't have it)
Result: ❌ ACCESS DENIED ← 🔒 ATTACK BLOCKED!
```

**Key insight:** Even with a correct password, attackers can't log in without the user's physical device.

---

## Implementation Details

### Packages Used

```xml
<PackageReference Include="Otp.NET" Version="1.4.1" />
<PackageReference Include="QRCoder" Version="1.7.0" />
```

- **Otp.NET**: TOTP generation and verification (RFC 6238 compliant)
- **QRCoder**: QR code generation for Google Authenticator

---

### Database Schema

Added two fields to `Users` table:

```csharp
public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    
    // MFA fields
    public bool MfaEnabled { get; set; } = false;
    public string? MfaSecret { get; set; }  // Base32-encoded secret
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
```

**Migration:**
```bash
dotnet ef migrations add AddMfaFields
dotnet ef database update
```

---

### MFA Service

**Location:** `Services/MfaService.cs`

#### Key Methods

**1. GenerateSecret() - Create random TOTP secret**
```csharp
public string GenerateSecret()
{
    var secretBytes = new byte[20]; // 160 bits (RFC 6238 recommendation)
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(secretBytes);
    }
    return Base32Encoding.ToString(secretBytes); // e.g., "4DSCID6JGWUA6RQB..."
}
```

**2. GenerateQrCodeDataUrl() - Create QR code for Google Authenticator**
```csharp
public string GenerateQrCodeDataUrl(string email, string secret, string issuer)
{
    // Format: otpauth://totp/Issuer:Email?secret=SECRET&issuer=Issuer
    var totpUri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}" +
                  $"?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
    
    // Generate QR code
    var qrGenerator = new QRCodeGenerator();
    var qrCodeData = qrGenerator.CreateQrCode(totpUri, QRCodeGenerator.ECCLevel.Q);
    var qrCode = new PngByteQRCode(qrCodeData);
    var qrCodeImage = qrCode.GetGraphic(20);
    
    // Convert to base64 data URL
    return $"data:image/png;base64,{Convert.ToBase64String(qrCodeImage)}";
}
```

**3. VerifyTotp() - Validate 6-digit code**
```csharp
public bool VerifyTotp(string secret, string code)
{
    var secretBytes = Base32Encoding.ToBytes(secret);
    var totp = new Totp(secretBytes);
    
    // Allow ±1 time step (30 seconds) for clock drift
    return totp.VerifyTotp(
        code, 
        out long timeStepMatched,
        new VerificationWindow(previous: 1, future: 1)
    );
}
```

---

### API Endpoints

#### 1. Enable MFA

**POST** `/api/auth/enable-mfa`

```json
Request:
{
  "userId": 1
}

Response:
{
  "success": true,
  "message": "MFA setup initiated...",
  "secret": "4DSCID6JGWUA6RQB...",
  "qrCodeDataUrl": "data:image/png;base64,iVBORw0KG...",
  "instructions": [
    "1. Install Google Authenticator on your phone",
    "2. Scan the QR code with the app",
    "3. Enter the 6-digit code to confirm setup",
    "4. Save the secret key as backup"
  ]
}
```

**What happens:**
1. Generates 20-byte random secret
2. Encodes as Base32 (required by TOTP)
3. Creates QR code with `otpauth://totp/...` URI
4. Saves secret to database (MFA not yet active)
5. Returns QR code for scanning

---

#### 2. Confirm MFA

**POST** `/api/auth/confirm-mfa`

```json
Request:
{
  "userId": 1,
  "code": "123456"
}

Response:
{
  "success": true,
  "message": "✅ MFA successfully enabled!",
  "mfaEnabled": true
}
```

**What happens:**
1. Verifies the 6-digit code matches current TOTP
2. Allows ±30 seconds for clock drift
3. If valid, sets `MfaEnabled = true`
4. User must now provide TOTP code on every login

---

#### 3. Login WITHOUT MFA Check (VULNERABLE)

**POST** `/api/auth/login-without-mfa`

```json
Request:
{
  "email": "user@test.com",
  "password": "Test123!"
}

Response:
{
  "success": true,
  "message": "⚠️ WARNING: You logged in without MFA verification even though MFA is enabled!",
  "token": "eyJhbGci...",
  "userId": 1,
  "email": "user@test.com",
  "mfaEnabled": true,
  "vulnerability": "This endpoint doesn't enforce MFA, making it vulnerable to credential stuffing attacks"
}
```

**The Problem:**
- Only checks password
- Ignores `MfaEnabled` field
- Attacker with stolen password can log in successfully!
- **This is what happens when MFA is optional or not enforced**

---

#### 4. Login WITH MFA Check (SECURE)

**POST** `/api/auth/login-with-mfa`

```json
Request:
{
  "email": "user@test.com",
  "password": "Test123!",
  "mfaCode": "123456"
}

Response (Success):
{
  "success": true,
  "message": "✅ Login successful with MFA verification",
  "token": "eyJhbGci...",
  "userId": 1,
  "email": "user@test.com",
  "mfaEnabled": true,
  "security": "Your account is protected by two-factor authentication"
}

Response (Missing MFA Code):
{
  "mfaRequired": true,
  "message": "MFA code required. Please enter the 6-digit code from Google Authenticator."
}

Response (Invalid MFA Code):
{
  "success": false,
  "message": "Invalid MFA code. Please check your authenticator app."
}
```

**The Solution:**
1. Checks password first
2. If `MfaEnabled == true`, requires TOTP code
3. Verifies code against shared secret
4. Only grants access if BOTH password and TOTP are valid
5. **Blocks credential stuffing attacks**

---

#### 5. Disable MFA

**POST** `/api/auth/disable-mfa`

```json
Request:
{
  "userId": 1,
  "password": "Test123!"
}

Response:
{
  "success": true,
  "message": "⚠️ MFA has been disabled. Your account is now less secure.",
  "mfaEnabled": false
}
```

**Security Note:**
- Requires password verification before disabling
- Prevents attackers from removing MFA if they gain temporary access
- Logs the action for audit purposes

---

## Testing Results

All 9 tests passed successfully! ✅

### Test Summary

| Test | Endpoint | Input | Expected | Result |
|------|----------|-------|----------|--------|
| 1 | Register | Email + Password | User created | ✅ Pass |
| 2 | Enable MFA | User ID | QR code returned | ✅ Pass |
| 3 | Confirm MFA | Invalid code | Rejected | ✅ Pass |
| 4 | Confirm MFA | Valid code | MFA activated | ✅ Pass |
| 5 | Login (vulnerable) | Password only | **Access granted** | ⚠️ Vulnerability demonstrated |
| 6 | Login (secure) | Password, no code | Access denied | ✅ Pass |
| 7 | Login (secure) | Invalid code | Access denied | ✅ Pass |
| 8 | Login (secure) | Valid code | Access granted | ✅ Pass |
| 9 | Disable MFA | Password | MFA disabled | ✅ Pass |

---

## Code Comparison: Vulnerable vs Secure

### ❌ VULNERABLE Login (Don't do this!)

```csharp
[HttpPost("login-without-mfa")]
public async Task<IActionResult> LoginWithoutMfa([FromBody] LoginRequest request)
{
    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
    
    // Check password
    var passwordValid = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
    if (passwordValid != PasswordVerificationResult.Success)
    {
        return BadRequest("Invalid credentials");
    }
    
    // ⚠️ PROBLEM: We're not checking user.MfaEnabled!
    // Attacker with stolen password can log in!
    
    var token = _jwtTokenService.GenerateToken(user);
    return Ok(new { token });
}
```

### ✅ SECURE Login (Do this!)

```csharp
[HttpPost("login-with-mfa")]
public async Task<IActionResult> LoginWithMfa([FromBody] LoginWithMfaRequest request)
{
    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
    
    // Step 1: Check password
    var passwordValid = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
    if (passwordValid != PasswordVerificationResult.Success)
    {
        return BadRequest("Invalid credentials");
    }
    
    // Step 2: Check if MFA is enabled
    if (user.MfaEnabled)
    {
        if (string.IsNullOrEmpty(request.MfaCode))
        {
            return BadRequest(new { mfaRequired = true, message = "MFA code required" });
        }
        
        // Step 3: Verify TOTP code
        var isMfaValid = _mfaService.VerifyTotp(user.MfaSecret!, request.MfaCode);
        if (!isMfaValid)
        {
            return BadRequest("Invalid MFA code");
        }
    }
    
    // ✅ Both password AND MFA verified!
    var token = _jwtTokenService.GenerateToken(user);
    return Ok(new { token });
}
```

---

## Google Authenticator Setup Flow

### User Experience

1. **User clicks "Enable MFA"**
   - App calls `/api/auth/enable-mfa`
   - Server generates secret and QR code
   - App displays QR code on screen

2. **User scans QR code with Google Authenticator**
   - QR code contains: `otpauth://totp/PasswordSecurityDemo:user@test.com?secret=...`
   - Google Authenticator extracts secret and starts generating codes
   - New code every 30 seconds

3. **User enters first code to confirm**
   - App calls `/api/auth/confirm-mfa` with code
   - Server verifies code matches
   - MFA is now active

4. **Every future login**
   - User enters email + password
   - User opens Google Authenticator
   - User enters current 6-digit code
   - Server verifies both password and TOTP
   - Access granted only if both are valid

---

## Security Benefits

### What MFA Prevents

✅ **Credential Stuffing** - Stolen passwords alone can't log in  
✅ **Password Reuse Attacks** - Breached password from Site A won't work on Site B  
✅ **Phishing** - Attackers need physical device, not just password  
✅ **Brute Force** - Even if password is guessed, TOTP still required  
✅ **Keyloggers** - TOTP code expires in 30 seconds, can't be reused  

### Real-World Impact

**Microsoft Study:**
- MFA blocks **99.9% of automated attacks**
- Even simple SMS codes are effective
- TOTP apps (Google Authenticator) are more secure than SMS

**Verizon Data Breach Report:**
- **81% of breaches** involve stolen or weak passwords
- **90%+ of login attempts** on some sites are credential stuffing
- MFA is the #1 defense against these attacks

---

## Best Practices

### ✅ DO

1. **Always enforce MFA** for sensitive operations (banking, admin panels, etc.)
2. **Never make MFA optional** for high-value accounts
3. **Allow ±1 time step** (30 seconds) for clock drift
4. **Provide backup codes** in case user loses phone
5. **Log MFA enable/disable events** for audit trail
6. **Require password verification** before disabling MFA
7. **Use TOTP (Google Authenticator)** instead of SMS (more secure)
8. **Educate users** on saving their secret key

### ❌ DON'T

1. **Don't ignore `MfaEnabled` field** during login
2. **Don't allow MFA bypass** through alternate endpoints
3. **Don't store secrets in plain text** (this demo does for simplicity, production should encrypt)
4. **Don't use short secrets** (minimum 160 bits / 20 bytes)
5. **Don't allow unlimited MFA attempts** (implement rate limiting)
6. **Don't rely on passwords alone** for sensitive accounts

---

## Files Modified/Created

### New Files

- `Services/MfaService.cs` - TOTP generation and verification
- `Models/MfaModels.cs` - Request/response DTOs
- `Migrations/[timestamp]_AddMfaFields.cs` - Database migration
- `test-mfa-simple.ps1` - Interactive test script
- `DEMO7-COMPLETE.md` - This documentation

### Modified Files

- `Models/User.cs` - Added `MfaEnabled` and `MfaSecret` fields
- `Controllers/AuthController.cs` - Added 5 MFA endpoints
- `Program.cs` - Registered `IMfaService` in dependency injection

---

## How to Test

### Prerequisites

- Google Authenticator app (iOS/Android)
- API running on `http://localhost:5000`

### Run Tests

```bash
# Start the API
dotnet run

# In another terminal, run tests
.\test-mfa-simple.ps1
```

### Manual Testing

1. Register a user via `/register-secure`
2. Call `/enable-mfa` with user ID
3. Scan QR code with Google Authenticator
4. Call `/confirm-mfa` with code from app
5. Try `/login-without-mfa` (vulnerable - works with just password)
6. Try `/login-with-mfa` (secure - requires password + code)

---

## Key Takeaways

1. **MFA adds a second factor** beyond "something you know"
2. **TOTP codes change every 30 seconds** and can't be reused
3. **Credential stuffing is blocked** even with correct passwords
4. **Always enforce MFA** - don't make it optional
5. **99.9% of attacks blocked** with proper MFA implementation

---

## Next Steps (Future Enhancements)

1. **Rate Limiting** - Limit MFA verification attempts
2. **Backup Codes** - Generate one-time recovery codes
3. **Secret Encryption** - Encrypt MFA secrets at rest
4. **Audit Logging** - Track all MFA events
5. **SMS Fallback** - Allow SMS codes as backup (less secure but better than nothing)
6. **WebAuthn** - Support hardware security keys (YubiKey, etc.)

---

## Conclusion

Successfully implemented **Multi-Factor Authentication** to demonstrate:
- How TOTP works (RFC 6238)
- How MFA blocks credential stuffing attacks
- The difference between vulnerable (password-only) and secure (password + MFA) login

**Result:** Even with a stolen password, attackers cannot access accounts protected by MFA!

🎉 **DEMO 7 COMPLETE!**
