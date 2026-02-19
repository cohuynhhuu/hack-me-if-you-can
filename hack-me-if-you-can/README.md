# Password Security Demo - ASP.NET Core Web API

## 🎯 Purpose
Educational demonstration of password security evolution from **insecure** to **secure** practices.

---

## 📚 Learning Path

### ✅ **DEMO 1: Plain Text Passwords** (Baseline - Insecure)
**📜 [Full Documentation: DEMO1-PASSWORD-SECURITY.md](DEMO1-PASSWORD-SECURITY.md)**

Demonstrates why storing passwords in plain text is dangerous:

- Anyone with DB access can see all passwords
- Database breach = complete account compromise
- Password hashing with PBKDF2 + automatic salt generation

**Key Learning:** Hashing is one-way (not reversible). Same password produces different hashes due to unique salts.

### ✅ **DEMO 2: Form Validation** (Input Protection)
**📜 [Full Documentation: DEMO2-VALIDATION.md](DEMO2-VALIDATION.md)**

Implements server-side validation to prevent invalid/malicious input:

- DataAnnotations validation (`[Required]`, `[EmailAddress]`, `[MinLength]`)
- Automatic ModelState validation
- Structured error responses
- Protection against SQL injection, XSS, and DoS attacks

**Key Learning:** Client-side validation is NOT security - it's UX. Server-side validation is MANDATORY.

### ✅ **DEMO 3: SQL Injection** (Database Attack Prevention)
**📜 [Full Documentation: DEMO3-SQL-INJECTION.md](DEMO3-SQL-INJECTION.md)**

Demonstrates SQL Injection attacks and prevention:

- **Vulnerable:** Raw SQL with string concatenation (`' OR 1=1 --`)
- **Secure:** Entity Framework LINQ (automatic parameterization)
- **Attacks Shown:** Authentication bypass, data exfiltration, always-true conditions
- **Defense:** Parameterized queries, ORM usage

**Key Learning:** String concatenation = SQL Injection. Parameterization = Safe.

**🧪 Test:** Run `.\test-sql-injection.ps1` to see attacks and defenses in action.

### ✅ **DEMO 4: XSS Prevention** (Cross-Site Scripting Defense)
**📜 [Full Documentation: DEMO4-XSS-PREVENTION.md](DEMO4-XSS-PREVENTION.md)**

Demonstrates XSS attacks and HTML encoding protection:

- **Vulnerable:** Raw HTML rendering of user input
- **Secure:** HttpUtility.HtmlEncode() prevents script execution
- **Attacks Shown:** `<script>alert('XSS')</script>`, `<img onerror>`, cookie theft
- **Defense:** HTML encoding, CSP headers, HttpOnly cookies

**Key Learning:** Always encode output. Never render user input as raw HTML.

**🧪 Test:** Run `.\test-xss.ps1` to see XSS attacks and encoding protection in action.

### ✅ **DEMO 5: CAPTCHA Protection** (Bot Attack Prevention)
**📜 [Full Documentation: DEMO5-CAPTCHA-PROTECTION.md](DEMO5-CAPTCHA-PROTECTION.md)**

Demonstrates bot attack prevention with Google reCAPTCHA:

- **Vulnerable:** No CAPTCHA - bots can attempt 10,000+ logins/minute
- **Secure:** Server-side CAPTCHA verification blocks automated attacks
- **Attacks Shown:** Credential stuffing, brute-force, account enumeration
- **Defense:** reCAPTCHA v2/v3, server-side validation with secret key

**Key Learning:** Client-side CAPTCHA is useless without server verification. Bots can bypass JavaScript but can't bypass Google's human detection.

**🧪 Test:** Open `http://localhost:5000/test-captcha.html` for interactive demo.

### ✅ **DEMO 6: JWT Authentication** (Stateless API Security)
**📜 [Full Documentation: DEMO6-COMPLETE.md](DEMO6-COMPLETE.md)**

Demonstrates JWT (JSON Web Token) authentication for modern APIs:

- **Vulnerable:** Session-based auth (server stores state, doesn't scale)
- **Secure:** JWT tokens (stateless, signed, self-contained)
- **Claims Included:** UserId, Email, Issuer, Audience, Expiration
- **Defense:** HMAC-SHA256 signature prevents tampering

**Key Learning:** JWT enables horizontal scaling. Tokens must be signed with secret key - any modification breaks signature and token is rejected.

**🧪 Test:** Run `.\test-jwt.ps1` to see JWT generation, validation, and `[Authorize]` protection.

### ✅ **DEMO 7: Multi-Factor Authentication (MFA)** (Blocks Credential Stuffing)
**📜 [Full Documentation: DEMO7-COMPLETE.md](DEMO7-COMPLETE.md)**

Demonstrates Google Authenticator (TOTP) integration:

- **Vulnerable:** Password-only login (stolen password = full access)
- **Secure:** Password + TOTP code from phone (2 factors required)
- **How TOTP Works:** 6-digit code changes every 30 seconds, can't be reused
- **Defense:** Blocks credential stuffing even with correct password

**Key Learning:** MFA blocks 99.9% of automated attacks. Even if attackers steal passwords from breaches, they can't log in without the user's phone.

**🧪 Test:** Run `.\test-mfa-simple.ps1` and scan QR code with Google Authenticator app.

### ✅ **DEMO 8: System Logging & Security Auditing**

**📜 [Full Documentation: DEMO8-COMPLETE.md](DEMO8-COMPLETE.md)**

Demonstrates comprehensive security logging with **dual storage**:

- **Vulnerable:** No logging (breaches undetected for months, no compliance proof)
- **Secure:** Logs to BOTH file (JSON) AND database (SQL Server) with IP, User-Agent, timestamp
- **What We Log:** Login success/failure, SQL injection, XSS, MFA events, JWT failures
- **What We DON'T Log:** Passwords, MFA codes, credit cards, API keys

**Key Learning:** Security logs aren't for debugging - they're for threat detection, forensics, and compliance. Dual storage provides fast file access for monitoring AND queryable database for long-term retention. Without logs, breaches take 197 days to detect (IBM). With logs: hours.

**🧪 Test:** Run `.\test-security-logging.ps1` to see events logged to `logs/security-logs-{date}.json` AND `SecurityLogs` database table.

### 🔜 **DEMO 9: Rate Limiting & Account Lockout** (Coming Next)

Will implement request throttling, temporary blocks, and distributed attack prevention.

---

## 🔐 Key Concepts

### **Hashing vs Encryption**

- **Encryption**: Reversible - can decrypt with a key
- **Hashing**: One-way function - mathematically impossible to reverse
- **Why Hash?** Even if DB is compromised, attackers can't read passwords

### **Server-Side Validation**

- **Why Mandatory:** Client-side validation can be bypassed (disable JS, use curl, bot scripts)
- **Protection:** SQL injection, XSS, DoS attacks, data corruption
- **Implementation:** DataAnnotations + ModelState validation

### **SQL Injection Prevention**

- **Vulnerable:** `$"SELECT * FROM Users WHERE Email = '{email}'"` ← Attacker controls SQL
- **Secure:** `_context.Users.Where(u => u.Email == email)` ← EF parameterizes automatically
- **Why It Works:** Parameters separate **code** from **data**
- **Attack Example:** `' OR 1=1 --` bypasses authentication in vulnerable code

### **XSS (Cross-Site Scripting) Prevention**

- **Vulnerable:** `$"<h1>Welcome, {name}!</h1>"` ← Script executes in browser
- **Secure:** `$"<h1>Welcome, {HttpUtility.HtmlEncode(name)}!</h1>"` ← Script displayed as text
- **Why It Works:** HTML encoding converts `<` to `&lt;`, breaking HTML structure
- **Attack Example:** `<script>alert('XSS')</script>` or `<img src=x onerror=alert('XSS')>`

### **Multi-Factor Authentication (MFA)**

- **What It Is:** Requires 2+ factors: something you know (password) + something you have (phone)
- **TOTP (Time-based OTP):** 6-digit code changes every 30 seconds based on shared secret + time
- **Credential Stuffing:** Attackers use stolen passwords from Site A to access Site B
- **How MFA Blocks It:** Even with correct password, attackers lack TOTP code (requires user's phone)
- **Real Impact:** Microsoft reports MFA blocks 99.9% of automated attacks

### **CAPTCHA (Bot Attack Prevention)**

- **Vulnerable:** No CAPTCHA = bots can try 10,000+ passwords/minute
- **Secure:** Server-side reCAPTCHA verification limits attacks to human speed
- **Why It Works:** Google's ML detects bots by behavior (mouse movement, timing, browser fingerprint)
- **Attack Example:** Credential stuffing uses leaked credentials from other breaches to test millions of login attempts

### **JWT Authentication (Stateless API Security)**

- **Vulnerable:** Session-based = server stores state, doesn't scale horizontally
- **Secure:** JWT tokens = stateless (no server storage), self-contained, signed
- **Why It Works:** Token format = `Header.Payload.Signature` - HMAC-SHA256 signature prevents tampering
- **Attack Example:** Attacker modifies userId in token payload → signature verification fails → token rejected

### **Security Logging & Auditing**

- **Vulnerable:** No logging = breaches undetected for months (avg 197 days), no compliance proof
- **Secure:** Dual storage - File logs (JSON) + Database (SQL Server) with structured security events
- **What We Log:** Authentication events, SQL injection, XSS, MFA events, JWT failures
- **What We DON'T Log:** Passwords, MFA codes, credit cards, secrets (privacy + compliance)
- **Why It Works:** Real-time threat detection, forensic timeline, compliance proof (GDPR, SOC 2)
- **Dual Storage Benefits:**
  - **File logs**: Fast, lightweight, real-time monitoring
  - **Database logs**: Queryable via SQL, long-term retention, compliance-ready
- **Log Levels:** Critical (active attacks) > Warning (suspicious) > Information (normal)
- **Real Impact:** Detect breaches in hours vs months, prove compliance, reduce breach cost from $4.45M

---

## 🚀 Quick Start

### 1. Restore & Build
```bash
dotnet restore
dotnet build
```

### 2. Run
```bash
dotnet run
```

API will be available at: `http://localhost:5000`

---

## 📡 API Endpoints

### **DEMO 1: Insecure Registration** (Shows the Problem)
```http
POST /api/auth/register-insecure
Content-Type: application/json

{
  "email": "bad@example.com",
  "password": "MyPassword123"
}
```
⚠️ **Danger**: Password stored as "MyPassword123" in database

---

### **DEMO 2: Secure Registration** (With Validation & Hashing)
```http
POST /api/auth/register-secure
Content-Type: application/json

{
  "email": "good@example.com",
  "password": "MyPassword123"
}
```
✅ **Protected**:

- Input validated (email format, password length)
- Password hashed: `AQAAAAEAACcQAAAAEFxP8vR3...XyZ` (89+ characters)
- Salt automatically included in hash

---

### **DEMO 2: Test Validation** (Invalid Inputs)

**Invalid Email:**
```bash
curl -X POST http://localhost:5000/api/auth/register-secure \
  -H "Content-Type: application/json" \
  -d '{"email":"not-an-email","password":"SecurePass123"}'
```

**Response:**
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": {
    "Email": ["Invalid email format"]
  }
}
```

**Password Too Short:**
```bash
curl -X POST http://localhost:5000/api/auth/register-secure \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"short"}'
```

**Response:**
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": {
    "Password": ["Password must be at least 8 characters long"]
  }
}
```

**📖 See [STEP2-VALIDATION.md](STEP2-VALIDATION.md) for complete validation testing guide.**

---

### **Login**
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "good@example.com",
  "password": "MyPassword123"
}
```

---

### **View All Users (Demo Only)**
```http
GET /api/auth/users
```
Shows side-by-side comparison of plain vs hashed passwords

---

## 🧪 Test Scenario

1. **Register insecure user**:
   ```bash
   curl -X POST http://localhost:5000/api/auth/register-insecure \
     -H "Content-Type: application/json" \
     -d '{"email":"hacker@target.com","password":"secret123"}'
   ```

2. **Register secure user**:
   ```bash
   curl -X POST http://localhost:5000/api/auth/register-secure \
     -H "Content-Type: application/json" \
     -d '{"email":"safe@user.com","password":"secret123"}'
   ```

3. **View the difference**:
   ```bash
   curl http://localhost:5000/api/auth/users
   ```

**Result**:
```json
[
  {
    "id": 1,
    "email": "hacker@target.com",
    "plainPassword": "secret123",        // ⚠️ VISIBLE!
    "passwordHash": "N/A"
  },
  {
    "id": 2,
    "email": "safe@user.com",
    "plainPassword": "N/A",
    "passwordHash": "AQAAAAEAACcQAAAA..."  // ✅ SAFE!
  }
]
```

---

## 🛡️ Why This Matters

### Scenario: Database Breach
```
📂 Database Dump Leaked

Insecure User:
- Email: admin@company.com
- Password: "Admin123!"  ← Attacker can login immediately

Secure User:
- Email: ceo@company.com  
- PasswordHash: "AQAAAAEAACcQAAAAEMx..." ← Useless to attacker
```

### Even Same Passwords Have Different Hashes
```
User 1: password → AQAAAAEAACcQAAAAEMx...
User 2: password → AQAAAAEAACcQAAAAFNy...
         ↑ Same      ↑ Different (unique salt)
```
Prevents **rainbow table** attacks!

---

## 📚 Learn More

- PasswordHasher uses **PBKDF2** (Password-Based Key Derivation Function 2)
- Default: 10,000 iterations (makes brute-force impractical)
- Salt prevents pre-computed hash attacks
- **Never** log or display passwords/hashes in production

---

## 🔧 Technologies

- **.NET 10** (Latest LTS)
- **ASP.NET Core Web API** (Minimal hosting model)
- **Entity Framework Core 10.0.2** (SQL Server provider)
- **SQL Server LocalDB** (Development database)
- **Microsoft.AspNetCore.Identity** (PasswordHasher with PBKDF2)
- **DataAnnotations** (Server-side validation)
