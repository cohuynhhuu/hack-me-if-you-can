#!/usr/bin/env pwsh
<#
.SYNOPSIS
    STEP 8: Security Logging Testing Script
.DESCRIPTION
    Demonstrates the difference between NO logging vs WITH logging
    and triggers various security events to populate the log files.
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

Write-Header "STEP 8: Security Logging Testing"

# Setup: Register a test user for login tests
Write-Header "Setup: Register Test User"
$testEmail = "logtest@example.com"
$testPassword = "SecureP@ss123"

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/register-secure" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
    } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
    
    Write-Success "✅ Test user registered: $testEmail"
}
catch {
    Write-Info "User already exists (continuing with existing user)"
}

# Test 1: Login WITHOUT logging (BAD)
Write-Header "Test 1: Login WITHOUT Logging (BAD)"
Write-Info "Attempting login with correct credentials..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-no-logging" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Success "✅ Login succeeded"
    Write-Fail "⚠️  PROBLEM: $($result.vulnerability)"
    Write-Info ""
}
catch {
    Write-Fail "❌ Login failed: $($_.Exception.Message)"
}

# Test 2: Failed login WITHOUT logging (BAD)
Write-Header "Test 2: Failed Login WITHOUT Logging (BAD)"
Write-Info "Attempting login with WRONG password..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-no-logging" -Method Post -Body (@{
        email = $testEmail
        password = "WrongPassword123"
    } | ConvertTo-Json) -ContentType "application/json"
}
catch {
    $error = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Info "Login blocked (expected)"
    Write-Fail "⚠️  PROBLEM: $($error.vulnerability)"
    Write-Info ""
}

# Test 3: Login WITH logging (GOOD)
Write-Header "Test 3: Login WITH Logging (GOOD)"
Write-Info "Attempting login with correct credentials..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-with-logging" -Method Post -Body (@{
        email = $testEmail
        password = $testPassword
    } | ConvertTo-Json) -ContentType "application/json"
    
    Write-Success "✅ Login succeeded"
    Write-Success "✅ SECURE: $($result.security)"
    Write-Info ""
}
catch {
    Write-Fail "❌ Login failed: $($_.Exception.Message)"
}

# Test 4: Failed login WITH logging (GOOD)
Write-Header "Test 4: Failed Login WITH Logging (GOOD)"
Write-Info "Attempting login with WRONG password..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-with-logging" -Method Post -Body (@{
        email = $testEmail
        password = "WrongPassword123"
    } | ConvertTo-Json) -ContentType "application/json"
}
catch {
    $error = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Success "✅ Login blocked (expected)"
    Write-Success "✅ SECURE: $($error.security)"
    Write-Info ""
}

# Test 5: SQL Injection Attempt Logging
Write-Header "Test 5: SQL Injection Attempt Logging"
$sqlPayloads = @(
    "admin' OR '1'='1",
    "'; DROP TABLE Users--",
    "1' OR '1'='1' --"
)

foreach ($payload in $sqlPayloads) {
    Write-Info "Testing SQL injection: $payload"
    
    try {
        $result = Invoke-RestMethod -Uri "$BaseUrl/test-sql-injection-logging" -Method Post -Body (@{
            input = $payload
        } | ConvertTo-Json) -ContentType "application/json"
    }
    catch {
        $error = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Success "🚨 $($error.security)"
        Write-Info "   Logged: EventType=$($error.logged.eventType), Severity=$($error.logged.severity)"
    }
}
Write-Info ""

# Test 6: XSS Attempt Logging
Write-Header "Test 6: XSS Attempt Logging"
$xssPayloads = @(
    "<script>alert('XSS')</script>",
    "javascript:alert(1)",
    "<img src=x onerror='alert(1)'>"
)

foreach ($payload in $xssPayloads) {
    Write-Info "Testing XSS payload: $payload"
    
    try {
        $result = Invoke-RestMethod -Uri "$BaseUrl/test-xss-logging" -Method Post -Body (@{
            input = $payload
        } | ConvertTo-Json) -ContentType "application/json"
    }
    catch {
        $error = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Success "🚨 $($error.security)"
        Write-Info "   Logged: EventType=$($error.logged.eventType), Severity=$($error.logged.severity)"
    }
}
Write-Info ""

# Test 7: MFA Failure Logging
Write-Header "Test 7: MFA Failure Logging"
Write-Info "Simulating MFA failure..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/test-mfa-failure-logging" -Method Post -ContentType "application/json"
    
    Write-Success "✅ $($result.security)"
    Write-Info "   Logged: EventType=$($result.logged.eventType), Severity=$($result.logged.severity)"
    Write-Info ""
}
catch {
    Write-Fail "❌ Test failed: $($_.Exception.Message)"
}

# Test 8: Unknown user login (triggers logging)
Write-Header "Test 8: Unknown User Login (Triggers Logging)"
Write-Info "Attempting login with non-existent user..."

try {
    $result = Invoke-RestMethod -Uri "$BaseUrl/login-with-logging" -Method Post -Body (@{
        email = "hacker@example.com"
        password = "SomePassword123"
    } | ConvertTo-Json) -ContentType "application/json"
}
catch {
    $error = $_.ErrorDetails.Message | ConvertFrom-Json
    Write-Success "✅ Unknown user login attempt logged"
    Write-Info "   EventType: LoginFailure, Reason: User not found"
    Write-Info ""
}

# Summary
Write-Header "Testing Complete - Check Log Files"

Write-Info ""
Write-Info "Security logs are written to:"
Write-Success "  📁 logs/security-logs-{date}.json"
Write-Info ""
Write-Info "View logs with:"
Write-Success "  Get-Content logs/security-logs-*.json | ConvertFrom-Json | Format-List"
Write-Info ""
Write-Success "✅ All security logging tests completed!"
Write-Info ""

# Display sample log entries
Write-Header "Sample Log Entries"
Write-Info "Checking for log files..."

$logFiles = Get-ChildItem -Path "logs" -Filter "security-logs-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($logFiles) {
    Write-Success "`nFound log file: $($logFiles.Name)"
    Write-Info "`nLast 5 security events:`n"
    
    $logContent = Get-Content $logFiles.FullName
    $lastFiveLines = $logContent | Select-Object -Last 5
    
    foreach ($line in $lastFiveLines) {
        try {
            $logEntry = $line | ConvertFrom-Json
            
            Write-Host "  [" -NoNewline
            Write-Host $logEntry.'@t' -ForegroundColor Yellow -NoNewline
            Write-Host "] " -NoNewline
            
            if ($logEntry.'@l' -eq 'Critical') {
                Write-Host $logEntry.'@l' -ForegroundColor Red -NoNewline
            }
            elseif ($logEntry.'@l' -eq 'Warning') {
                Write-Host $logEntry.'@l' -ForegroundColor Yellow -NoNewline
            }
            else {
                Write-Host $logEntry.'@l' -ForegroundColor Green -NoNewline
            }
            
            Write-Host " - " -NoNewline
            Write-Host $logEntry.'@mt'
        }
        catch {
            # Skip non-JSON lines
        }
    }
    
    Write-Info "`n"
    Write-Info "Full log available at: $($logFiles.FullName)"
}
else {
    Write-Fail "`n⚠️  No log files found. Make sure the API is running."
}

Write-Info ""
Write-Success "🎉 STEP 8 Security Logging testing complete!"
Write-Info ""
Write-Info "Key Takeaways:"
Write-Info "  • Without logging: No visibility into security events"
Write-Info "  • With logging: Full audit trail for compliance & forensics"
Write-Info "  • Structured logs: Easy to search and analyze"
Write-Info "  • Critical events: SQL injection, XSS flagged immediately"
Write-Info "  • Dual storage: File logs (JSON) + Database (SQL Server)"
Write-Info ""

# Query Database Logs
Write-Header "Database Logs (SQL Server)"
Write-Info "Querying SecurityLogs table..."

try {
    # Connection string (LocalDB)
    $connectionString = "Server=(localdb)\MSSQLLocalDB;Database=PasswordSecurityDemo;Trusted_Connection=True;"
    
    # Query last 10 security events from database
    $query = @"
SELECT TOP 10 
    Id,
    Timestamp,
    EventType,
    Email,
    IpAddress,
    LogLevel,
    Message
FROM SecurityLogs
ORDER BY Timestamp DESC
"@
    
    $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
    $command = New-Object System.Data.SqlClient.SqlCommand($query, $connection)
    
    $connection.Open()
    $reader = $command.ExecuteReader()
    
    Write-Success "`nLast 10 security events from database:`n"
    
    $count = 0
    while ($reader.Read()) {
        $count++
        $timestamp = $reader["Timestamp"]
        $eventType = $reader["EventType"]
        $logLevel = $reader["LogLevel"]
        $email = $reader["Email"]
        $ip = $reader["IpAddress"]
        $message = $reader["Message"]
        
        Write-Host "  [$timestamp] " -NoNewline
        
        if ($logLevel -eq "Critical") {
            Write-Host $logLevel -ForegroundColor Red -NoNewline
        }
        elseif ($logLevel -eq "Warning") {
            Write-Host $logLevel -ForegroundColor Yellow -NoNewline
        }
        else {
            Write-Host $logLevel -ForegroundColor Green -NoNewline
        }
        
        Write-Host " - $eventType"
        Write-Host "    Email: $email | IP: $ip" -ForegroundColor Gray
        Write-Host "    $message" -ForegroundColor Gray
        Write-Host ""
    }
    
    $reader.Close()
    $connection.Close()
    
    if ($count -eq 0) {
        Write-Info "No logs found in database yet. Run more tests to populate logs."
    }
    else {
        Write-Success "✅ $count security events found in database"
        Write-Info ""
        Write-Info "Query database with SQL:"
        Write-Success "  SELECT * FROM SecurityLogs ORDER BY Timestamp DESC"
        Write-Info ""
        Write-Info "Benefits of dual logging:"
        Write-Info "  📁 File logs: Fast, lightweight, good for real-time monitoring"
        Write-Info "  🗄️  Database logs: Queryable, long-term retention, compliance-ready"
    }
}
catch {
    Write-Fail "`n⚠️  Could not query database: $($_.Exception.Message)"
    Write-Info "Make sure the API is running to apply the migration."
}

Write-Info ""
