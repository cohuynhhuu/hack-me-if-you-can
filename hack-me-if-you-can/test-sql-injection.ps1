# STEP 3 - SQL Injection Attack & Defense Demo

$baseUrl = "http://localhost:5000/api/auth"

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  🔐 STEP 3: SQL Injection - Attack & Defense Demo" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Setup: Register test users
Write-Host "📝 Setup: Creating test users..." -ForegroundColor Yellow

$users = @(
    @{ email = "victim@test.com"; password = "VictimPass123" },
    @{ email = "admin@test.com"; password = "AdminSecret999" }
)

foreach ($user in $users) {
    $body = $user | ConvertTo-Json
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/register-insecure" `
            -ContentType "application/json" -Body $body -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  ✓ Created: $($user.email)" -ForegroundColor Green
    } catch {
        Write-Host "  - User already exists: $($user.email)" -ForegroundColor DarkGray
    }
}

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  💀 ATTACK PHASE - Exploiting Vulnerable Endpoints" -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""

# Attack 1: Comment Injection
Write-Host "🔴 ATTACK 1: SQL Comment Injection (--)" -ForegroundColor Red
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Technique: Comment out password check" -ForegroundColor White
Write-Host "  Payload: victim@test.com'-- " -ForegroundColor Yellow
Write-Host "  Goal: Login without knowing password`n" -ForegroundColor White

try {
    $result = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/login-vulnerable?email=victim@test.com'--&password=WRONG_PASSWORD"
    
    Write-Host "  💥 BREACH SUCCESSFUL!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "  ├─ Logged in as: $($result.user.email)" -ForegroundColor Red
    Write-Host "  ├─ User ID: $($result.user.id)" -ForegroundColor Red
    Write-Host "  └─ SQL: $($result.sqlExecuted)" -ForegroundColor Yellow
    Write-Host ""
} catch {
    Write-Host "  ✅ Attack blocked" -ForegroundColor Green
}

Start-Sleep -Seconds 1

# Attack 2: OR 1=1 (Always True)
Write-Host "🔴 ATTACK 2: Always True Condition (OR 1=1)" -ForegroundColor Red
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Technique: Make WHERE clause always true" -ForegroundColor White
Write-Host "  Payload: ' OR 1=1 -- " -ForegroundColor Yellow
Write-Host "  Goal: Login as first user (usually admin)`n" -ForegroundColor White

try {
    $email = "' OR 1=1 --"
    $result = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/login-vulnerable?email=$email&password="
    
    Write-Host "  💥 BREACH SUCCESSFUL!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "  ├─ Logged in as: $($result.user.email)" -ForegroundColor Red
    Write-Host "  ├─ User ID: $($result.user.id)" -ForegroundColor Red
    Write-Host "  ├─ Bypassed ALL authentication!" -ForegroundColor Red
    Write-Host "  └─ SQL: $($result.sqlExecuted)" -ForegroundColor Yellow
    Write-Host ""
} catch {
    Write-Host "  ✅ Attack blocked" -ForegroundColor Green
}

Start-Sleep -Seconds 1

# Attack 3: Data Exfiltration
Write-Host "🔴 ATTACK 3: Data Exfiltration (Dump All Passwords)" -ForegroundColor Red
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Technique: Use OR 1=1 to bypass filter" -ForegroundColor White
Write-Host "  Payload: ' OR 1=1 -- " -ForegroundColor Yellow
Write-Host "  Goal: Extract all user emails and passwords`n" -ForegroundColor White

try {
    $query = "' OR 1=1 --"
    $result = Invoke-RestMethod -Method Get `
        -Uri "$baseUrl/search-vulnerable?query=$query"
    
    Write-Host "  💥 DATA BREACH!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "  ├─ Extracted $($result.results.Count) user records" -ForegroundColor Red
    Write-Host "  ├─ Including passwords!" -ForegroundColor Red
    Write-Host "  └─ SQL: $($result.sqlExecuted)" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "  📊 Stolen Data:" -ForegroundColor Magenta
    foreach ($user in $result.results) {
        Write-Host "    ├─ Email: $($user.email)" -ForegroundColor White
        Write-Host "    └─ Password: $($user.password)" -ForegroundColor Red
    }
    Write-Host ""
} catch {
    Write-Host "  ✅ Attack blocked" -ForegroundColor Green
}

Start-Sleep -Seconds 1

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  🛡️ DEFENSE PHASE - Testing Secure Endpoints" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

# Defense Test 1: Secure Login (EF LINQ)
Write-Host "🛡️ DEFENSE TEST 1: Secure Login (Entity Framework LINQ)" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Same payload: ' OR 1=1 -- " -ForegroundColor Yellow
Write-Host "  Method: Parameterized query via EF Core`n" -ForegroundColor White

$body = @{
    email = "' OR 1=1 --"
    password = ""
} | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Method Post -Uri "$baseUrl/login-secure" `
        -ContentType "application/json" -Body $body
    Write-Host "  ❌ Defense failed (unexpected)" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✅ PROTECTED!" -ForegroundColor Green -BackgroundColor Black
        Write-Host "  ├─ Status: 401 Unauthorized" -ForegroundColor Green
        Write-Host "  ├─ Message: Invalid credentials" -ForegroundColor Green
        Write-Host "  └─ Injection treated as literal text" -ForegroundColor Green
        Write-Host ""
    }
}

Start-Sleep -Seconds 1

# Defense Test 2: Secure Search (EF LINQ)
Write-Host "🛡️ DEFENSE TEST 2: Secure Search (Entity Framework LINQ)" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Same payload: ' OR 1=1 -- " -ForegroundColor Yellow
Write-Host "  Method: Parameterized query via EF Core`n" -ForegroundColor White

try {
    $query = "' OR 1=1 --"
    $result = Invoke-RestMethod -Method Get `
        -Uri "$baseUrl/search-secure?query=$query"
    
    Write-Host "  ✅ PROTECTED!" -ForegroundColor Green -BackgroundColor Black
    Write-Host "  ├─ Status: 200 OK" -ForegroundColor Green
    Write-Host "  ├─ Results: $($result.results.Count) (searching for literal string)" -ForegroundColor Green
    Write-Host "  ├─ No SQL injection executed" -ForegroundColor Green
    Write-Host "  └─ $($result.info)" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Host "  ✅ Attack blocked" -ForegroundColor Green
}

Start-Sleep -Seconds 1

# Defense Test 3: Parameterized Raw SQL
Write-Host "🛡️ DEFENSE TEST 3: Parameterized Raw SQL" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Same payload: ' OR 1=1 -- " -ForegroundColor Yellow
Write-Host "  Method: Raw SQL with parameters`n" -ForegroundColor White

try {
    $query = "' OR 1=1 --"
    $result = Invoke-RestMethod -Method Get `
        -Uri "$baseUrl/search-parameterized?query=$query"
    
    Write-Host "  ✅ PROTECTED!" -ForegroundColor Green -BackgroundColor Black
    Write-Host "  ├─ Status: 200 OK" -ForegroundColor Green
    Write-Host "  ├─ Results: $($result.results.Count)" -ForegroundColor Green
    Write-Host "  ├─ Parameters prevent injection" -ForegroundColor Green
    Write-Host "  └─ $($result.info)" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Host "  ✅ Attack blocked" -ForegroundColor Green
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 FINAL RESULTS:" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  🔴 Vulnerable Endpoints (String Concatenation):" -ForegroundColor Red
Write-Host "    ├─ ❌ Login bypassed (comment injection)" -ForegroundColor Red
Write-Host "    ├─ ❌ Authentication defeated (OR 1=1)" -ForegroundColor Red
Write-Host "    └─ ❌ Data breach (all passwords exposed)" -ForegroundColor Red
Write-Host ""
Write-Host "  🛡️ Secure Endpoints (Parameterized Queries):" -ForegroundColor Green
Write-Host "    ├─ ✅ EF LINQ: All attacks blocked" -ForegroundColor Green
Write-Host "    ├─ ✅ Parameterized SQL: All attacks blocked" -ForegroundColor Green
Write-Host "    └─ ✅ No data exposed" -ForegroundColor Green
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  ⚠️ KEY TAKEAWAY" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ❌ NEVER use string concatenation for SQL queries" -ForegroundColor Red
Write-Host "  ✅ ALWAYS use parameterized queries or ORM (EF Core)" -ForegroundColor Green
Write-Host ""
Write-Host "  String Concatenation = SQL Injection 💥" -ForegroundColor Red
Write-Host "  Parameterization = Safe ✅" -ForegroundColor Green
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
