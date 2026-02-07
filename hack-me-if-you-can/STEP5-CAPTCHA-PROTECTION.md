# STEP 5: CAPTCHA Protection (Bot Prevention)

## 🎯 Learning Objectives

By the end of this step, you will understand:
- What credential stuffing attacks are and how they work
- Why CAPTCHA is critical for preventing automated attacks
- How to integrate Google reCAPTCHA v2/v3
- Why CAPTCHA must be verified server-side (never trust the client!)
- The difference between reCAPTCHA v2 (checkbox) and v3 (invisible score)
- Real-world bot attack scenarios and prevention strategies

---

## 🤖 The Problem: Bot Attacks

### What Are Automated Attacks?

**Automated attacks** use scripts, bots, and tools to perform actions at scale that would be impossible for humans:

```
Human:  1 login attempt per second = 3,600/hour
Bot:    10,000 login attempts per second = 36,000,000/hour
```

**Without protection**, a single attacker with one bot can:
- Test millions of password combinations
- Create thousands of fake accounts
- Scrape sensitive data
- Overwhelm servers (DDoS)

---

## 💀 Attack Scenario 1: Credential Stuffing

### What Is Credential Stuffing?

**Credential stuffing** is an automated attack where attackers use **leaked credentials** from other breaches to try logging into your application.

### How It Works:

```
STEP 1: Attacker obtains leaked credentials from data breaches
├─ Database leak from Company A (2 million email:password pairs)
├─ Database leak from Company B (5 million credentials)
└─ Dark web credential databases (hundreds of millions)

STEP 2: Attacker uses automated tool to test credentials
├─ Bot sends 10,000 login requests per minute
├─ Uses real email addresses and passwords from breaches
└─ Tests credentials against YOUR application

STEP 3: Successful logins give attacker access
├─ Many users reuse passwords across sites
├─ Attacker gains access to valid accounts
└─ Can steal data, make purchases, send spam
```

### Real Example:

```
Attacker has: victim@email.com : Password123
(from LinkedIn breach)

Bot tries this on YOUR site:
POST /api/auth/login
{
  "email": "victim@email.com",
  "password": "Password123"
}

If victim reused password → BREACH!
```

---

## 💀 Attack Scenario 2: Brute-Force Login

### What Is Brute-Force?

Systematically trying every possible password combination until one works.

### How It Works:

```
For email: admin@company.com

Bot tries:
├─ password
├─ Password1
├─ Password123
├─ Admin123
├─ Company123
├─ ... (millions more)
```

**Without rate limiting or CAPTCHA:**
- Bot can try thousands of passwords per minute
- Eventually finds the correct one
- Gains unauthorized access

---

## 💀 Attack Scenario 3: Account Enumeration

### What Is Account Enumeration?

Finding valid email addresses/usernames in your system.

### How It Works:

```
Bot tests emails:
POST /api/auth/login
{
  "email": "test1@email.com",
  "password": "wrong"
}

Response time differences or error messages reveal:
├─ "Invalid credentials" → Email exists
├─ "User not found" → Email doesn't exist
└─ Attacker builds list of valid accounts to target
```

---

## 💀 Attack Scenario 4: Fake Account Creation

### The Problem:

Bots create thousands of fake accounts to:
- Send spam
- Manipulate ratings/reviews
- Claim promotional offers repeatedly
- Perform fraudulent transactions
- Skew analytics data

### Scale Without Protection:

```
Human registration: ~10 per hour
Bot registration: ~10,000 per hour
```

**Result:** Your database filled with fake accounts, server overload, degraded service.

---

## 🛡️ The Solution: CAPTCHA (Completely Automated Public Turing test to tell Computers and Humans Apart)

### What Is CAPTCHA?

A challenge-response test to determine whether the user is human or a bot.

### Types of CAPTCHA:

#### 1. **reCAPTCHA v2 (Checkbox)**

User clicks "I'm not a robot" checkbox.

**Pros:**
- Explicit user interaction
- Clear verification
- Works without JavaScript in fallback mode

**Cons:**
- Adds friction to user experience
- Can annoy legitimate users

**Use When:**
- High-security scenarios
- Suspicious behavior detected
- Critical operations (password reset, financial transactions)

---

#### 2. **reCAPTCHA v3 (Invisible Score-Based)**

Runs invisibly, assigns a score (0.0 - 1.0) to each request:
- **1.0** = Very likely human
- **0.5** = Uncertain
- **0.0** = Very likely bot

**Pros:**
- No user friction
- Seamless experience
- Adaptive security

**Cons:**
- Requires JavaScript
- Must handle edge cases (score interpretation)

**Use When:**
- All user-facing forms
- Want minimal user disruption
- Can handle score-based logic

---

## ⚠️ Critical Security Rule: Server-Side Verification

### Why Client-Side CAPTCHA Is Useless:

```javascript
// ❌ VULNERABLE: Client-side only
<form onsubmit="if(grecaptcha.getResponse()) submit()">
```

**Problem:** Attacker bypasses JavaScript:
```bash
curl -X POST /api/auth/login \
  -d '{"email":"victim@email.com", "password":"Password123"}'
  
# No CAPTCHA check → Bot attack succeeds!
```

### ✅ Correct Approach: Always Verify Server-Side

```
Client                          Server
  │                               │
  ├─ User solves CAPTCHA         │
  │                               │
  ├─ Get token from Google       │
  │                               │
  ├─ Send token to server ────►  │
  │                               │
  │                          ┌────┴────┐
  │                          │ Verify  │
  │                          │ token   │
  │                          │ with    │
  │                          │ Google  │
  │                          └────┬────┘
  │                               │
  │                          Valid? ────► Proceed
  │                               │
  │                          Invalid? ───► Reject
```

**Why This Works:**
1. Attacker can't forge Google's response
2. Server validates with secret key (unknown to client)
3. Google confirms token is legitimate
4. Only then does server process request

---

## 🔐 Implementation: Google reCAPTCHA Integration

### Step 1: Get reCAPTCHA Keys

1. Go to [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin)
2. Register your site
3. Choose version (v2 or v3)
4. Get:
   - **Site Key** (public, goes in HTML)
   - **Secret Key** (private, goes in server config)

### Step 2: Configure Server

**appsettings.json:**
```json
{
  "ReCaptcha": {
    "SiteKey": "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
    "SecretKey": "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe",
    "Version": "v2",
    "MinimumScore": 0.5
  }
}
```

**Note:** Above keys are Google's test keys (always return success). For production, use your real keys!

### Step 3: Create CAPTCHA Verification Service

**Services/CaptchaService.cs:**
```csharp
public interface ICaptchaService
{
    Task<CaptchaVerificationResult> VerifyAsync(string token, string? remoteIp = null);
}

public class CaptchaService : ICaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private const string GoogleVerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

    public async Task<CaptchaVerificationResult> VerifyAsync(string token, string? remoteIp = null)
    {
        var secretKey = _configuration["ReCaptcha:SecretKey"];

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("secret", secretKey),
            new KeyValuePair<string, string>("response", token),
            new KeyValuePair<string, string>("remoteip", remoteIp ?? "")
        });

        var response = await _httpClient.PostAsync(GoogleVerifyUrl, content);
        var json = await response.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<CaptchaVerificationResult>(json);
    }
}
```

### Step 4: Register Service

**Program.cs:**
```csharp
builder.Services.AddHttpClient<ICaptchaService, CaptchaService>();
```

### Step 5: Protect Endpoints

**Controllers/AuthController.cs:**
```csharp
[HttpPost("login-with-captcha")]
public async Task<IActionResult> LoginWithCaptcha([FromBody] LoginWithCaptchaRequest request)
{
    // STEP 1: Verify CAPTCHA first (before any business logic!)
    var captchaResult = await _captchaService.VerifyAsync(request.CaptchaToken);

    if (!captchaResult.Success)
    {
        return BadRequest(new { message = "CAPTCHA verification failed" });
    }

    // STEP 2: Proceed with normal login logic only after CAPTCHA verification
    // ... password verification code ...
}
```

---

## 📊 CAPTCHA Verification Flow

### Request Flow:

```
1. User fills login form
2. User solves CAPTCHA (v2) or it runs invisibly (v3)
3. Google reCAPTCHA returns token
4. Frontend sends token + credentials to server
5. Server verifies token with Google API
6. Google responds with success/failure
7. Server proceeds with login only if CAPTCHA valid
```

### Google Verification API Response:

```json
{
  "success": true,
  "challenge_ts": "2026-02-07T12:00:00Z",
  "hostname": "example.com",
  "score": 0.9,  // v3 only
  "action": "login"  // v3 only
}
```

**Error Response:**
```json
{
  "success": false,
  "error-codes": [
    "invalid-input-response",
    "timeout-or-duplicate"
  ]
}
```

### Common Error Codes:

| Code | Meaning | Solution |
|------|---------|----------|
| `missing-input-secret` | Secret key not provided | Check server config |
| `invalid-input-secret` | Secret key invalid | Verify keys from Google |
| `missing-input-response` | Token not provided | Check client code |
| `invalid-input-response` | Token invalid/expired | User must solve CAPTCHA again |
| `timeout-or-duplicate` | Token used twice or expired | Generate new token |

---

## 🔬 Demonstration Endpoints

### 1. Vulnerable Login (No CAPTCHA)

**Endpoint:** `POST /api/auth/login-no-captcha`

**Request:**
```json
{
  "email": "victim@test.com",
  "password": "Password123"
}
```

**Why Vulnerable:**
- No bot detection
- Attacker can send millions of requests
- Credential stuffing succeeds
- Brute-force attacks possible

**Attack Demonstration:**
```bash
# Bot script can do this 10,000 times per minute
for email in leaked_emails:
    for password in leaked_passwords:
        POST /api/auth/login-no-captcha
        # No CAPTCHA check → Eventually finds valid combo
```

---

### 2. Protected Login (With CAPTCHA)

**Endpoint:** `POST /api/auth/login-with-captcha`

**Request:**
```json
{
  "email": "user@test.com",
  "password": "Password123",
  "captchaToken": "03AGdBq27..."
}
```

**Why Secure:**
- CAPTCHA token required
- Server verifies with Google
- Bots can't generate valid tokens
- Automated attacks blocked

**Attack Prevention:**
```bash
# Bot tries attack
POST /api/auth/login-with-captcha
{
  "email": "victim@email.com",
  "password": "Password123",
  "captchaToken": "fake-token"
}

# Server Response:
{
  "success": false,
  "message": "CAPTCHA verification failed",
  "error": "Bot detected"
}

# Attack blocked! ✅
```

---

### 3. Protected Registration

**Endpoint:** `POST /api/auth/register-with-captcha`

**Request:**
```json
{
  "email": "newuser@test.com",
  "password": "SecurePass123",
  "captchaToken": "03AGdBq27..."
}
```

**Protection:**
- Prevents mass fake account creation
- Blocks automated spam registrations
- Stops promotional abuse

---

### 4. Test CAPTCHA Verification

**Endpoint:** `POST /api/auth/test-captcha`

**Purpose:** Test CAPTCHA verification without side effects

**Request:**
```json
{
  "captchaToken": "03AGdBq27..."
}
```

**Response:**
```json
{
  "success": true,
  "details": {
    "score": 0.9,
    "action": "test",
    "challengeTs": "2026-02-07T12:00:00Z",
    "hostname": "localhost",
    "remoteIp": "127.0.0.1"
  }
}
```

---

## 🎨 Frontend Integration

### reCAPTCHA v2 (Checkbox) Example:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Login with CAPTCHA</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <form id="loginForm">
        <input type="email" id="email" placeholder="Email" required>
        <input type="password" id="password" placeholder="Password" required>
        
        <!-- reCAPTCHA v2 Widget -->
        <div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>
        
        <button type="submit">Login</button>
    </form>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const captchaToken = grecaptcha.getResponse();
            
            if (!captchaToken) {
                alert('Please complete the CAPTCHA');
                return;
            }
            
            const response = await fetch('/api/auth/login-with-captcha', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: document.getElementById('email').value,
                    password: document.getElementById('password').value,
                    captchaToken: captchaToken
                })
            });
            
            const result = await response.json();
            alert(result.message);
        });
    </script>
</body>
</html>
```

---

### reCAPTCHA v3 (Invisible) Example:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Login with Invisible CAPTCHA</title>
    <script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>
</head>
<body>
    <form id="loginForm">
        <input type="email" id="email" placeholder="Email" required>
        <input type="password" id="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Execute reCAPTCHA v3 invisibly
            grecaptcha.ready(async () => {
                const token = await grecaptcha.execute('YOUR_SITE_KEY', {
                    action: 'login'
                });
                
                const response = await fetch('/api/auth/login-with-captcha', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: document.getElementById('email').value,
                        password: document.getElementById('password').value,
                        captchaToken: token
                    })
                });
                
                const result = await response.json();
                alert(result.message);
            });
        });
    </script>
</body>
</html>
```

---

## 📊 Impact Analysis

### Without CAPTCHA:

| Threat | Feasibility | Impact |
|--------|-------------|--------|
| **Credential Stuffing** | ⚠️ High - Millions of attempts/hour | Account takeover, data breach |
| **Brute Force** | ⚠️ High - Unlimited attempts | Password cracking, unauthorized access |
| **Fake Accounts** | ⚠️ High - Thousands/minute | Spam, fraud, database pollution |
| **Account Enumeration** | ⚠️ High - Instant results | Targeted attacks, phishing |
| **DDoS** | ⚠️ High - Overwhelming requests | Service disruption, downtime |

### With CAPTCHA:

| Threat | Feasibility | Impact |
|--------|-------------|--------|
| **Credential Stuffing** | ✅ Low - ~1 attempt/minute | Prevented - too slow to be effective |
| **Brute Force** | ✅ Low - Human-limited | Prevented - computational infeasible |
| **Fake Accounts** | ✅ Low - Manual only | Prevented - can't scale |
| **Account Enumeration** | ✅ Low - Rate limited | Significantly slowed |
| **DDoS** | ✅ Medium - Some mitigation | Reduced - bots blocked |

---

## 🎓 Best Practices

### ✅ DO:

1. **Always verify server-side** - Never trust client
2. **Use HTTPS** - Encrypt CAPTCHA tokens in transit
3. **Check IP addresses** - Pass remoteIp to Google for better detection
4. **Handle errors gracefully** - Don't reveal security details
5. **Set reasonable score thresholds** - v3: 0.5+ recommended
6. **Combine with rate limiting** - Defense in depth
7. **Monitor CAPTCHA failures** - Detect attack patterns
8. **Use test keys in development** - Google provides them

### ❌ DON'T:

1. **Don't verify client-side only** - Bots bypass JavaScript
2. **Don't expose secret key** - Keep in server config only
3. **Don't reuse tokens** - One-time use only
4. **Don't skip validation** - Always check Google response
5. **Don't block all v3 low scores** - May affect legitimate users
6. **Don't hardcode keys** - Use configuration files
7. **Don't ignore error codes** - They indicate issues
8. **Don't forget HTTPS** - Tokens must be encrypted

---

## 🔍 Testing Strategy

### Test 1: Verify CAPTCHA Requirement

```bash
# Try login without CAPTCHA token
curl -X POST http://localhost:5000/api/auth/login-with-captcha \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Password123"}'

# Expected: 400 Bad Request - "CAPTCHA token is required"
```

### Test 2: Invalid Token

```bash
# Try with fake token
curl -X POST http://localhost:5000/api/auth/login-with-captcha \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Password123","captchaToken":"fake"}'

# Expected: 400 Bad Request - "CAPTCHA verification failed"
```

### Test 3: Valid Token

Use the HTML demo page to generate valid tokens and test.

---

## 🧪 Google Test Keys

For development/testing, Google provides keys that always succeed:

**Site Key:** `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`  
**Secret Key:** `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe`

**These work on:**
- localhost
- Any test domain
- Always return success

**⚠️ Never use test keys in production!**

---

## 📊 Real-World Statistics

### Industry Data:

- **90-95%** of login attempts can be bots during attacks
- **60%** of web traffic is non-human (bots, scrapers)
- **Credential stuffing** accounts for **40%** of login attempts for retailers
- CAPTCHA reduces bot traffic by **80-90%**
- reCAPTCHA v3 blocks **99.9%** of automated attacks

### Cost of Bot Attacks:

- **Average credential stuffing attack:** 300K-1M requests
- **Cost per breach:** $4.24M average (IBM 2023)
- **Fake account cleanup:** $5-50 per account
- **DDoS downtime:** $300K-$5M per hour

---

## 💡 Advanced Topics

### Adaptive CAPTCHA Challenge

```csharp
// Show CAPTCHA only when suspicious activity detected
if (IsLoginAttemptSuspicious(email, ipAddress))
{
    // Require CAPTCHA
    return BadRequest(new { requiresCaptcha = true });
}
else
{
    // Allow login without CAPTCHA
}
```

### Score-Based v3 Logic

```csharp
var result = await _captchaService.VerifyAsync(token);

if (result.Score < 0.3)
{
    // Very likely bot - reject
    return BadRequest(new { message = "Bot detected" });
}
else if (result.Score < 0.7)
{
    // Uncertain - require additional verification
    return Ok(new { requiresMFA = true });
}
else
{
    // Likely human - proceed normally
}
```

---

## 📚 Additional Resources

- [Google reCAPTCHA Documentation](https://developers.google.com/recaptcha)
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
- [Bot Detection Best Practices](https://www.cloudflare.com/learning/bots/how-to-block-bad-bots/)

---

## 🚀 Next Steps

Combine CAPTCHA with:
- **Rate Limiting** - Limit requests per IP/user
- **Account Lockout** - Lock after N failed attempts
- **IP Reputation** - Block known malicious IPs
- **Device Fingerprinting** - Detect suspicious devices
- **Behavioral Analysis** - Monitor user patterns

---

**Remember:** CAPTCHA is ONE layer of defense. Always implement multiple security measures for comprehensive protection!
