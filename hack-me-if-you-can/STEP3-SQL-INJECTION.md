# 🔐 STEP 3: SQL Injection - Understanding and Prevention

## 🎯 Goal
Demonstrate how SQL Injection attacks work and how to prevent them using parameterized queries and ORMs.

---

## ⚠️ What is SQL Injection?

**SQL Injection** is a code injection technique where attackers insert malicious SQL code into application queries, allowing them to:
- **Bypass authentication** (login without credentials)
- **Extract sensitive data** (dump entire database)
- **Modify data** (update/delete records)
- **Execute admin operations** (drop tables, create accounts)
- **Take over the server** (in extreme cases)

### 🏆 Impact
- **#3 on OWASP Top 10** (2021)
- Affects **millions of applications**
- Can lead to **complete system compromise**

---

## 🔴 VULNERABLE Example: String Concatenation

### **The Dangerous Code**

```csharp
// ❌ NEVER DO THIS!
var sql = $"SELECT * FROM Users WHERE Email = '{email}' AND Password = '{password}'";
var users = await _context.Users.FromSqlRaw(sql).ToListAsync();
```

### **What the Developer Intended**

Normal login with email `admin@example.com` and password `MyPass123`:

```sql
SELECT * FROM Users 
WHERE Email = 'admin@example.com' AND Password = 'MyPass123'
```

**Result:** Returns user if credentials match. ✅

---

### **What the Attacker Does**

Attacker enters:
- **Email:** `admin@example.com' --`
- **Password:** `anything`

**Generated SQL:**
```sql
SELECT * FROM Users 
WHERE Email = 'admin@example.com' --' AND Password = 'anything'
```

**What Happens:**
- `--` is SQL comment symbol
- Everything after `--` is **ignored**
- Password check is **completely bypassed**!

**Result:** Attacker logs in as admin **without knowing the password**! 🔴

---

### **Even Worse Attack: Dump All Passwords**

Attacker uses SQL Injection payload in search:

**Malicious Query:**
```
' OR 1=1 --
```

**Generated SQL:**
```sql
SELECT Id, Email, Password FROM Users 
WHERE Email LIKE '%' OR 1=1 --%'
```

**What Happens:**
- `1=1` is **always true**
- Query returns **ALL USERS**
- Attacker gets **every password in the database**!

**Result:** Complete database breach! 💥

---

## 🧪 Testing SQL Injection Attacks

### **Prerequisites:**
1. Register a test user with plain-text password:
```powershell
$body = @{
    email = "victim@example.com"
    password = "SecretPassword123"
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
    -Uri "http://localhost:5000/api/auth/register-insecure" `
    -ContentType "application/json" -Body $body
```

---

### **Attack 1: Bypass Login (Comment Injection)**

**Vulnerable Endpoint:**
```
POST /api/auth/login-vulnerable?email=victim@example.com'--&password=wrong
```

**PowerShell Test:**
```powershell
# Attacker doesn't know the password but uses SQL Injection
Invoke-RestMethod -Method Post `
    -Uri "http://localhost:5000/api/auth/login-vulnerable?email=victim@example.com'--&password=anything"

# Result: Login successful WITHOUT knowing the password!
```

**SQL Executed:**
```sql
-- Intended query:
SELECT * FROM Users WHERE Email = 'victim@example.com' AND Password = 'wrong'

-- Actual query (after injection):
SELECT * FROM Users WHERE Email = 'victim@example.com'--' AND Password = 'wrong'
--                                                     ↑
--                          Everything after this is a comment (ignored)
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful (VULNERABLE method)",
  "warning": "⚠️ This endpoint is vulnerable to SQL Injection!",
  "user": {
    "id": 1,
    "email": "victim@example.com"
  },
  "sqlExecuted": "SELECT * FROM Users WHERE Email = 'victim@example.com'--' AND Password = 'wrong'"
}
```

---

### **Attack 2: Always True Condition (OR 1=1)**

**Vulnerable Endpoint:**
```
POST /api/auth/login-vulnerable?email=' OR 1=1 --&password=
```

**PowerShell Test:**
```powershell
# Login as FIRST user in database (usually admin)
$email = "' OR 1=1 --"
Invoke-RestMethod -Method Post `
    -Uri "http://localhost:5000/api/auth/login-vulnerable?email=$($email)&password="

# Result: Logs in as the first user (often admin account)!
```

**SQL Executed:**
```sql
SELECT * FROM Users WHERE Email = '' OR 1=1 --' AND Password = ''
--                                    ↑
--                           This is ALWAYS TRUE
```

**Why It Works:**
- `OR 1=1` makes the condition **always true**
- Returns **all users** (query picks first one)
- Attacker logs in **without any credentials**!

---

### **Attack 3: Data Exfiltration (UNION Injection)**

**Vulnerable Endpoint:**
```
GET /api/auth/search-vulnerable?query=' UNION SELECT Id, Email, Password FROM Users --
```

**PowerShell Test:**
```powershell
$query = "' UNION SELECT Id, Email, Password FROM Users --"
Invoke-RestMethod -Method Get `
    -Uri "http://localhost:5000/api/auth/search-vulnerable?query=$query"

# Result: Returns ALL users with their passwords!
```

**SQL Executed:**
```sql
SELECT Id, Email, Password FROM Users 
WHERE Email LIKE '%' UNION SELECT Id, Email, Password FROM Users --%'
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "id": 1,
      "email": "victim@example.com",
      "password": "SecretPassword123"
    },
    {
      "id": 2,
      "email": "admin@example.com",
      "password": "Admin2024!"
    }
    // ... ALL users exposed!
  ]
}
```

---

### **Attack 4: Blind SQL Injection (Boolean-Based)**

**Technique:** Infer information by observing TRUE/FALSE responses

**Test if admin exists:**
```powershell
# Check if admin@example.com exists
$query = "' AND (SELECT COUNT(*) FROM Users WHERE Email='admin@example.com')>0 --"
Invoke-RestMethod -Method Post `
    -Uri "http://localhost:5000/api/auth/login-vulnerable?email=$query&password="
```

**Response:**
- **Different response if admin exists** (TRUE)
- **Error or no results if not** (FALSE)

Attacker can **enumerate all data** character by character!

---

## ✅ SECURE Examples: Prevention Techniques

### **Method 1: Entity Framework LINQ (Recommended)**

```csharp
// ✅ SAFE: Entity Framework automatically parameterizes
var user = await _context.Users
    .Where(u => u.Email.ToLower() == email.ToLower())
    .Where(u => u.Password == password)
    .FirstOrDefaultAsync();
```

**Generated SQL (Parameterized):**
```sql
exec sp_executesql N'SELECT TOP(1) [u].[Id], [u].[Email], [u].[Password]
FROM [Users] AS [u]
WHERE (LOWER([u].[Email]) = @__email_0) AND ([u].[Password] = @__password_1)',
N'@__email_0 nvarchar(4000),@__password_1 nvarchar(4000)',
@__email_0=N'victim@example.com',@__password_1=N'SecretPassword123'
```

**Why It's Safe:**
- Email and password are **separate parameters**
- SQL engine treats `' OR 1=1 --` as **literal text**, not SQL code
- **Impossible to inject malicious SQL**

---

### **Method 2: Parameterized Raw SQL**

```csharp
// ✅ SAFE: Parameters prevent injection
var searchPattern = $"%{query}%";
var users = await _context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Email LIKE {0}", searchPattern)
    .ToListAsync();
```

**Why It's Safe:**
- `{0}` is a **parameter placeholder**
- EF Core automatically creates SQL parameters
- User input is **never concatenated** into SQL string

---

### **Method 3: ADO.NET with SqlParameter**

```csharp
// ✅ SAFE: Using SqlParameter objects
using var command = new SqlCommand(
    "SELECT * FROM Users WHERE Email = @Email AND Password = @Password", 
    connection);

command.Parameters.AddWithValue("@Email", email);
command.Parameters.AddWithValue("@Password", password);

var reader = await command.ExecuteReaderAsync();
```

**Why It's Safe:**
- Parameters are **strongly typed**
- Database knows which parts are **code** vs **data**
- SQL Injection payloads are treated as **literal strings**

---

## 🧪 Testing SECURE Endpoints

### **Test 1: SECURE Login (EF LINQ)**

**Attempt SQL Injection:**
```powershell
$body = @{
    email = "' OR 1=1 --"
    password = "anything"
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
    -Uri "http://localhost:5000/api/auth/login-secure" `
    -ContentType "application/json" -Body $body
```

**Result:**
```json
{
  "success": false,
  "message": "Invalid credentials"
}
```

**Why Attack Failed:**
- Entity Framework treats `' OR 1=1 --` as **literal email string**
- No user has that email
- **Attack completely neutralized** ✅

---

### **Test 2: SECURE Search (EF LINQ)**

**Attempt SQL Injection:**
```powershell
$query = "' OR 1=1 --"
Invoke-RestMethod -Method Get `
    -Uri "http://localhost:5000/api/auth/search-secure?query=$query"
```

**Result:**
```json
{
  "success": true,
  "message": "Search completed (SECURE method)",
  "info": "✅ Entity Framework LINQ prevents SQL Injection",
  "results": []
}
```

**Why Attack Failed:**
- EF searches for emails **containing** the literal string `' OR 1=1 --`
- No such email exists
- No data exposed ✅

---

### **Test 3: Parameterized Raw SQL**

**Attempt SQL Injection:**
```powershell
$query = "' UNION SELECT 1,2,3 --"
Invoke-RestMethod -Method Get `
    -Uri "http://localhost:5000/api/auth/search-parameterized?query=$query"
```

**Result:** No injection - query searches for literal string `' UNION SELECT 1,2,3 --`

---

## 📊 Comparison: Vulnerable vs Secure

| Aspect | Vulnerable (String Concat) | Secure (Parameterized) |
|--------|---------------------------|------------------------|
| **Code** | `$"...'{userInput}'..."` | `"...{0}", userInput` |
| **SQL Generated** | `WHERE Email = 'input'` | `WHERE Email = @p0` |
| **User Input** | Treated as **SQL code** | Treated as **data** |
| **' OR 1=1 --** | Executes as SQL | Literal text search |
| **Attack Success** | ✅ YES - Full breach | ❌ NO - Safe |
| **Best Practice** | ❌ NEVER USE | ✅ ALWAYS USE |

---

## 🛡️ How Parameterization Stops SQL Injection

### **The Problem: String Concatenation**

```csharp
// User input: admin' --
var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
// Result: SELECT * FROM Users WHERE Email = 'admin' --'
//                                                  ↑
//                                    SQL code injected!
```

---

### **The Solution: Parameterization**

```csharp
// User input: admin' --
var user = await _context.Users
    .Where(u => u.Email == email)
    .FirstOrDefaultAsync();

// Generated SQL:
// exec sp_executesql 
//   N'SELECT TOP(1) * FROM Users WHERE Email = @p0',
//   N'@p0 nvarchar(4000)',
//   @p0=N'admin'' --'
//                  ↑
//           Escaped apostrophe - treated as data, not code!
```

**What Happens:**
1. SQL engine receives **two separate pieces**:
   - **SQL Code:** `SELECT TOP(1) * FROM Users WHERE Email = @p0`
   - **Data:** `@p0 = 'admin'' --'`

2. Database **knows** `@p0` is data, not code
3. Special characters (`'`, `--`, `;`) are **automatically escaped**
4. **Impossible to inject SQL**

---

## 🔍 Real-World SQL Injection Exploits

### **1. Authentication Bypass**
```sql
-- Attacker input: admin' --
SELECT * FROM Users WHERE Email = 'admin' --' AND Password = 'anything'
-- Logs in as admin without password
```

---

### **2. Data Exfiltration**
```sql
-- Attacker input: ' UNION SELECT username, password, credit_card FROM Customers --
SELECT * FROM Products WHERE Name LIKE '%' UNION SELECT username, password, credit_card FROM Customers --%'
-- Dumps all customer data including credit cards
```

---

### **3. Data Manipulation**
```sql
-- Attacker input: '; UPDATE Users SET IsAdmin = 1 WHERE Email = 'attacker@evil.com' --
SELECT * FROM Users WHERE Email = ''; UPDATE Users SET IsAdmin = 1 WHERE Email = 'attacker@evil.com' --'
-- Grants admin privileges to attacker
```

---

### **4. Database Destruction**
```sql
-- Attacker input: '; DROP TABLE Users --
SELECT * FROM Products WHERE Id = ''; DROP TABLE Users --'
-- Deletes entire Users table!
```

---

## 🚨 Common Vulnerable Patterns

### **❌ String Concatenation**
```csharp
var sql = "SELECT * FROM Users WHERE Id = " + userId;
var sql = $"SELECT * FROM Users WHERE Name = '{name}'";
var sql = "SELECT * FROM Users WHERE Email = '" + email + "'";
```

### **❌ String.Format**
```csharp
var sql = String.Format("SELECT * FROM Users WHERE Email = '{0}'", email);
```

### **❌ String Interpolation**
```csharp
var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
```

---

## ✅ Secure Patterns

### **✅ Entity Framework LINQ**
```csharp
var users = await _context.Users
    .Where(u => u.Email == email)
    .ToListAsync();
```

### **✅ Parameterized Raw SQL (EF Core)**
```csharp
var users = await _context.Users
    .FromSqlRaw("SELECT * FROM Users WHERE Email = {0}", email)
    .ToListAsync();
```

### **✅ SqlParameter (ADO.NET)**
```csharp
command.CommandText = "SELECT * FROM Users WHERE Email = @Email";
command.Parameters.AddWithValue("@Email", email);
```

### **✅ Stored Procedures**
```csharp
await _context.Users
    .FromSqlRaw("EXEC GetUserByEmail @Email", 
        new SqlParameter("@Email", email))
    .ToListAsync();
```

---

## 📝 Best Practices

### **Always:**
1. ✅ Use **Entity Framework LINQ** (automatically parameterized)
2. ✅ Use **parameterized queries** for raw SQL
3. ✅ Use **SqlParameter** objects
4. ✅ Validate and sanitize input
5. ✅ Use **least privilege** database accounts
6. ✅ Enable **SQL logging** for monitoring

### **Never:**
1. ❌ Concatenate user input into SQL strings
2. ❌ Use `String.Format` or `$"..."` for SQL
3. ❌ Trust client-side validation alone
4. ❌ Run database with admin/root privileges
5. ❌ Display raw SQL errors to users
6. ❌ Assume input is safe "because it's validated"

---

## 🧪 Testing Script

Save as `test-sql-injection.ps1`:

```powershell
$baseUrl = "http://localhost:5000/api/auth"

Write-Host "`n🧪 STEP 3: SQL Injection Testing" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Setup: Register a test user
Write-Host "📝 Setup: Registering test user..." -ForegroundColor Yellow
$body = @{
    email = "victim@test.com"
    password = "TestPass123"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "$baseUrl/register-insecure" `
    -ContentType "application/json" -Body $body | Out-Null

Write-Host "✅ Test user created`n" -ForegroundColor Green

# Attack 1: Comment Injection
Write-Host "🔴 ATTACK 1: SQL Comment Injection (Bypass Login)" -ForegroundColor Red
Write-Host "Payload: email=victim@test.com'--&password=wrong`n"

try {
    $result = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/login-vulnerable?email=victim@test.com'--&password=wrong"
    
    Write-Host "💥 BREACH! Logged in without password!" -ForegroundColor Red
    Write-Host "SQL Executed: $($result.sqlExecuted)`n" -ForegroundColor Yellow
} catch {
    Write-Host "✅ Attack blocked`n" -ForegroundColor Green
}

# Attack 2: OR 1=1
Write-Host "🔴 ATTACK 2: Always True Condition (OR 1=1)" -ForegroundColor Red
Write-Host "Payload: email=' OR 1=1 --&password=`n"

try {
    $email = [uri]::EscapeDataString("' OR 1=1 --")
    $result = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/login-vulnerable?email=$email&password="
    
    Write-Host "💥 BREACH! Logged in as: $($result.user.email)" -ForegroundColor Red
    Write-Host "SQL Executed: $($result.sqlExecuted)`n" -ForegroundColor Yellow
} catch {
    Write-Host "✅ Attack blocked`n" -ForegroundColor Green
}

# Defense Test: Secure Endpoint
Write-Host "🛡️ DEFENSE TEST: Secure Login (Same Payload)" -ForegroundColor Green
Write-Host "Payload: email=' OR 1=1 --&password=`n"

$body = @{
    email = "' OR 1=1 --"
    password = ""
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/login-secure" `
        -ContentType "application/json" -Body $body
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "✅ PROTECTED! Attack failed - Invalid credentials`n" -ForegroundColor Green
    }
}

Write-Host "📊 CONCLUSION:" -ForegroundColor Cyan
Write-Host "  🔴 Vulnerable endpoints: BREACHED" -ForegroundColor Red
Write-Host "  🛡️ Secure endpoints: PROTECTED" -ForegroundColor Green
Write-Host "`n⚠️ NEVER use string concatenation for SQL queries!" -ForegroundColor Yellow
```

---

## 📖 Summary

### **How SQL Injection Works:**
1. Attacker enters **malicious SQL** instead of normal data
2. Application **concatenates** input into SQL string
3. Database **executes** the malicious SQL
4. Attacker **controls** the query logic

### **How to Prevent:**
1. Use **Entity Framework LINQ** (automatic parameterization)
2. Use **parameterized queries** for raw SQL
3. **Never concatenate** user input into SQL
4. Validate and sanitize input
5. Apply **principle of least privilege**

### **Key Takeaway:**
```
User Input + String Concatenation = SQL Injection 💥
User Input + Parameterization = Safe ✅
```

---

## 🚀 Next Steps

- ✅ **STEP 1:** Plain text passwords
- ✅ **STEP 2:** Form validation
- ✅ **STEP 3:** SQL Injection prevention
- ⏭️ **STEP 4:** Password hashing best practices
- ⏭️ **STEP 5:** Rate limiting & brute-force protection

---

**Remember: SQL Injection is preventable. Always use parameterized queries!** 🔒
