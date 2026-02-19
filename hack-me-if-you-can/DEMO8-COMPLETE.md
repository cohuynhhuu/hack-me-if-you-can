# DEMO 8: System Logging & Security Auditing

## 🎯 Overview

In this step, we implement **comprehensive security logging** with **dual storage**:

- **File Logs**: JSON structured logs via **Serilog** (fast, real-time monitoring)
- **Database Logs**: SQL Server table (queryable, long-term retention, compliance)

This demonstrates why logging is **NOT just for debugging** – it's essential for:

- **Security Monitoring**: Detect attacks in real-time
- **Incident Response**: Investigate breaches
- **Forensics**: Understand what happened after an attack
- **Compliance**: Meet GDPR, SOC 2, PCI-DSS requirements
- **Threat Detection**: Identify patterns of malicious activity

## ❌ What We DON'T Log (Critical)

**NEVER log sensitive data:**

- ❌ Passwords (plain text or hashed)
- ❌ MFA codes or secrets
- ❌ Credit card numbers
- ❌ Social Security Numbers
- ❌ API keys or tokens (full values)

**Why?** Logs are:
- Stored in plain text files AND databases
- Accessible to operations teams
- Backed up to multiple locations
- Subject to regulatory requirements
- Used for compliance audits (GDPR, SOC 2, PCI-DSS)

## ✅ What We DO Log

**Security Events:**

- ✅ Login success/failure
- ✅ Invalid password attempts
- ✅ SQL injection attempts
- ✅ XSS payload detection
- ✅ CAPTCHA failures
- ✅ JWT validation failures
- ✅ MFA events (enable, disable, success, failure)
- ✅ Unauthorized access attempts

**Context for Each Event:**

- Timestamp (UTC)
- User ID (if available)
- Email (if available)
- IP Address
- User-Agent
- Event Type
- Custom message

## 🔑 Key Concepts

### Application Logs vs Security Logs vs Audit Logs

| Type | Purpose | Examples | Retention |
|------|---------|----------|-----------|
| **Application Logs** | Debugging, performance | Exceptions, slow queries | Days to weeks |
| **Security Logs** | Threat detection, incident response | Failed logins, SQL injection | Months to years |
| **Audit Logs** | Compliance, legal | Data access, changes | Years (legally required) |

### Why We Use Dual Logging

**File Logs (Serilog)**:

1. **Structured Logging**: JSON output that's easy to search and analyze
2. **Multiple Sinks**: Write to console, files, databases, cloud services
3. **Log Levels**: Information, Warning, Error, Critical
4. **Fast & Efficient**: Minimal performance impact
5. **Real-time**: Immediate writes, good for monitoring

**Database Logs (SQL Server)**:

1. **Queryable**: Use SQL to filter, aggregate, and analyze
2. **Long-term Retention**: Keep logs for years (compliance)
3. **Relational**: Join with Users table, filter by date ranges
4. **Backup**: Automatic database backups include logs
5. **Compliance-Ready**: Easy to prove data access for audits

## 📦 What We Built

### 1. Security Log Models

**File**: `Models/SecurityLogModels.cs` (for file logging)

**File**: `Models/SecurityLog.cs` (for database logging)

```csharp
public enum SecurityEventType
{
    // Authentication
    LoginSuccess,
    LoginFailure,
    InvalidPassword,
    
    // MFA
    MfaEnabled, MfaDisabled, MfaSuccess, MfaFailure,
    
    // Threats
    SqlInjectionAttempt,
    XssAttemptDetected,
    InvalidCaptcha,
    
    // JWT
    JwtValidationFailure,
    JwtExpired,
    JwtInvalidSignature,
    
    // Authorization
    UnauthorizedAccess,
    ForbiddenAccess,
    
    // Account
    AccountCreated,
    AccountDeleted,
    PasswordChanged
}

public class SecurityLogEntry
{
    public DateTime Timestamp { get; set; }
    public SecurityEventType EventType { get; set; }
    public string? UserId { get; set; }
    public string? Email { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string Message { get; set; }
    public Dictionary<string, object>? AdditionalData { get; set; }
}
```

### 2. Database Entity

**File**: `Models/SecurityLog.cs`

```csharp
public class SecurityLog
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string EventType { get; set; }
    public string? UserId { get; set; }
    public string? Email { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string Message { get; set; }
    public string LogLevel { get; set; }
    public string? AdditionalDataJson { get; set; }
}
```

**Database Table**: `SecurityLogs` (created via EF Core migration)

### 3. SecurityLogService

**File**: `Services/SecurityLogService.cs`

**Purpose**: Centralized service for all security logging

**Dual Logging**: Writes to BOTH file (Serilog) AND database (SQL Server)

**Key Methods**:

- `LogSecurityEvent(SecurityLogEntry)` - Generic logging
- `LogLoginSuccess(...)` - Track successful logins
- `LogLoginFailure(...)` - Track failed logins
- `LogSqlInjectionAttempt(...)` - Track SQL injection
- `LogXssAttempt(...)` - Track XSS attacks
- `LogMfaEvent(...)` - Track MFA events
- `DetermineLogLevel(...)` - Map event type to severity

**Log Levels Mapping**:

| Event Type | Log Level | Reason |
|------------|-----------|--------|
| SQL Injection | **Critical** | Active attack in progress |
| XSS Attempt | **Critical** | Active attack in progress |
| Login Failure | **Warning** | Could be brute force attack |
| Invalid Password | **Warning** | Could be credential stuffing |
| MFA Failure | **Warning** | Could be account takeover |
| Login Success | **Information** | Normal operation |

### 4. Serilog Configuration

**File**: `Program.cs`

```csharp
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("System", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File(
        new CompactJsonFormatter(),
        path: "logs/security-logs-.json",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30)
    .CreateLogger();
```

**What This Does**:

- Logs to **Console** (for development)
- Logs to **JSON files** in `logs/` directory
- **Rolling logs**: New file each day
- **Retention**: Keep last 30 days (configurable)
- **Structured format**: JSON for easy parsing

### 5. Controller Integration

**File**: `Controllers/AuthController.cs`

Added helper methods:

```csharp
private string GetClientIp() => 
    HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

private string GetUserAgent() => 
    HttpContext.Request.Headers["User-Agent"].ToString() ?? "unknown";
```

Injected `SecurityLogService`:

```csharp
public AuthController(..., SecurityLogService securityLog)
{
    _securityLog = securityLog;
}
```

## 📋 API Endpoints

### 1. `POST /api/auth/login-no-logging` (BAD)

**Purpose**: Demonstrate login WITHOUT any logging

**Request**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ss123"
}
```

**Vulnerability**:
```json
{
  "success": true,
  "message": "Login successful",
  "vulnerability": "⚠️ No audit trail - Can't investigate breaches"
}
```

**Problem**: No visibility into:
- Who logged in
- When they logged in
- From what IP address
- Failed login attempts

### 2. `POST /api/auth/login-with-logging` (GOOD)

**Purpose**: Demonstrate login WITH comprehensive logging

**Request**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ss123"
}
```

**Success Response**:
```json
{
  "success": true,
  "message": "Login successful",
  "token": "eyJhbGc...",
  "security": "✅ Login event logged - Full audit trail available"
}
```

**What Gets Logged**:
```json
{
  "@t": "2026-02-08T18:30:15.123Z",
  "@l": "Information",
  "@mt": "SecurityEvent: LoginSuccess | User: user@example.com (123) | IP: 127.0.0.1",
  "EventType": "LoginSuccess",
  "Email": "user@example.com",
  "UserId": "123",
  "IpAddress": "127.0.0.1",
  "UserAgent": "Mozilla/5.0...",
  "Message": "User logged in without MFA"
}
```

**Failed Login Attempt**:
```json
{
  "@t": "2026-02-08T18:30:20.456Z",
  "@l": "Warning",
  "@mt": "SecurityEvent: InvalidPassword | User: user@example.com (123) | IP: 127.0.0.1",
  "EventType": "InvalidPassword",
  "Message": "Invalid password attempt"
}
```

### 3. `POST /api/auth/test-sql-injection-logging`

**Purpose**: Trigger SQL injection detection logging

**Request**:
```json
{
  "input": "admin' OR '1'='1"
}
```

**Response**:
```json
{
  "success": false,
  "message": "Malicious input detected",
  "security": "🚨 SQL injection attempt logged to security log",
  "logged": {
    "eventType": "SqlInjectionAttempt",
    "severity": "CRITICAL",
    "ipAddress": "127.0.0.1",
    "suspiciousInput": "admin' OR '1'='1"
  }
}
```

**Log Entry**:
```json
{
  "@t": "2026-02-08T18:30:25.789Z",
  "@l": "Critical",
  "@mt": "SecurityEvent: SqlInjectionAttempt | User: anonymous (N/A) | IP: 127.0.0.1",
  "EventType": "SqlInjectionAttempt",
  "Message": "SQL injection attempt detected",
  "AdditionalData": {
    "SuspiciousInput": "admin' OR '1'='1"
  }
}
```

### 4. `POST /api/auth/test-xss-logging`

**Purpose**: Trigger XSS detection logging

**Request**:
```json
{
  "input": "<script>alert('XSS')</script>"
}
```

**Response**:
```json
{
  "success": false,
  "message": "Malicious content detected",
  "security": "🚨 XSS attempt logged to security log",
  "logged": {
    "eventType": "XssAttemptDetected",
    "severity": "CRITICAL"
  }
}
```

### 5. `POST /api/auth/test-mfa-failure-logging`

**Purpose**: Demonstrate MFA failure logging

**Response**:
```json
{
  "success": false,
  "message": "MFA verification failed",
  "security": "✅ MFA failure logged - Multiple failures could indicate account takeover",
  "logged": {
    "eventType": "MfaFailure",
    "severity": "WARNING"
  }
}
```

## 🧪 Testing

### Run Test Script

```powershell
.\test-security-logging.ps1
```

**What It Tests**:

- 8 security event scenarios
- Logs written to BOTH file and database
- Queries database to display last 10 events

**Output**:
```
======================================================================
DEMO 8: Security Logging Testing
======================================================================

Test 1: Login WITHOUT Logging (BAD)
✅ Login succeeded
⚠️  PROBLEM: ⚠️ No audit trail - Can't investigate breaches

Test 3: Login WITH Logging (GOOD)
✅ Login succeeded
✅ SECURE: ✅ Login event logged - Full audit trail available

Test 5: SQL Injection Attempt Logging
Testing SQL injection: admin' OR '1'='1
🚨 SQL injection attempt logged to security log
   Logged: EventType=SqlInjectionAttempt, Severity=CRITICAL

Test 6: XSS Attempt Logging
Testing XSS payload: <script>alert('XSS')</script>
🚨 XSS attempt logged to security log
   Logged: EventType=XssAttemptDetected, Severity=CRITICAL

✅ All security logging tests completed!
```

### View Logs

**File Logs**:

**Location**: `logs/security-logs-{date}.json`

**View logs**:
```powershell
Get-Content logs/security-logs-*.json | ConvertFrom-Json | Format-List
```

**Database Logs**:

**Table**: `SecurityLogs`

**View logs via SQL**:
```sql
SELECT TOP 100 * 
FROM SecurityLogs 
ORDER BY Timestamp DESC
```

**View logs via PowerShell** (test script does this automatically):
```powershell
$connectionString = "Server=(localdb)\MSSQLLocalDB;Database=PasswordSecurityDemo;Trusted_Connection=True;"
$query = "SELECT TOP 10 * FROM SecurityLogs ORDER BY Timestamp DESC"
# ... execute query
```

**Search for specific events**:
```powershell
Get-Content logs/security-logs-*.json | 
    ConvertFrom-Json | 
    Where-Object { $_.'@mt' -like '*SqlInjection*' } |
    Format-List
```

**Count events by type**:
```powershell
Get-Content logs/security-logs-*.json | 
    ConvertFrom-Json | 
    Group-Object -Property '@mt' | 
    Select-Object Count, Name | 
    Sort-Object Count -Descending
```

## �️ Advanced Database Queries

The database logs enable powerful SQL queries for compliance and threat detection:

### Find All SQL Injection Attempts

```sql
SELECT Timestamp, IpAddress, UserAgent, Message, AdditionalDataJson
FROM SecurityLogs
WHERE EventType = 'SqlInjectionAttempt'
ORDER BY Timestamp DESC
```

### Detect Brute Force Patterns

```sql
-- Find IPs with 5+ failed logins in 10 minutes
SELECT IpAddress, COUNT(*) as FailedAttempts,
       MIN(Timestamp) as FirstAttempt, MAX(Timestamp) as LastAttempt
FROM SecurityLogs
WHERE EventType IN ('LoginFailure', 'InvalidPassword')
  AND Timestamp > DATEADD(minute, -10, GETDATE())
GROUP BY IpAddress
HAVING COUNT(*) >= 5
ORDER BY FailedAttempts DESC
```

### Audit Trail for Specific User

```sql
-- All security events for user in last 30 days
SELECT Timestamp, EventType, LogLevel, IpAddress, Message
FROM SecurityLogs
WHERE Email = 'user@example.com'
  AND Timestamp > DATEADD(day, -30, GETDATE())
ORDER BY Timestamp DESC
```

### Critical Events Dashboard

```sql
-- Count critical events by type (last 24 hours)
SELECT EventType, COUNT(*) as Count,
       MIN(Timestamp) as FirstOccurrence, MAX(Timestamp) as LastOccurrence
FROM SecurityLogs
WHERE LogLevel = 'Critical'
  AND Timestamp > DATEADD(hour, -24, GETDATE())
GROUP BY EventType
ORDER BY Count DESC
```

### Benefits of Dual Logging

| Aspect | File Logs | Database Logs |
|--------|-----------|---------------|
| **Speed** | ✅ Very fast | ⚠️ Transactions |
| **Queries** | ❌ Grep only | ✅ Full SQL |
| **Retention** | ⚠️ Manual | ✅ Automatic backups |
| **Compliance** | ⚠️ Hard to prove | ✅ Easy reports |
| **Aggregation** | ❌ Limited | ✅ GROUP BY, JOIN |
| **Real-time** | ✅ Immediate | ⚠️ Slight delay |

**Best Practice**: Use BOTH for optimal security monitoring!

## �🔍 Real-World Examples

### Example 1: Detecting Brute Force Attack

**Scenario**: Attacker tries multiple passwords

**Log entries**:
```json
[2026-02-08 18:30:00] Warning - LoginFailure | user@example.com | IP: 192.168.1.100
[2026-02-08 18:30:05] Warning - LoginFailure | user@example.com | IP: 192.168.1.100
[2026-02-08 18:30:10] Warning - LoginFailure | user@example.com | IP: 192.168.1.100
[2026-02-08 18:30:15] Warning - LoginFailure | user@example.com | IP: 192.168.1.100
[2026-02-08 18:30:20] Warning - LoginFailure | user@example.com | IP: 192.168.1.100
```

**Detection**: 5 failed logins in 20 seconds from same IP

**Response**:
1. Block IP address (rate limiting - DEMO 9)
2. Alert security team
3. Notify user (password reset email)

### Example 2: Investigating Account Takeover

**Scenario**: User reports suspicious activity

**Security team queries logs**:
```powershell
# Find all logins for user in last 24 hours
Get-Content logs/security-logs-*.json | 
    ConvertFrom-Json | 
    Where-Object { 
        $_.Email -eq 'victim@example.com' -and 
        $_.'@t' -gt (Get-Date).AddDays(-1) 
    } |
    Format-Table '@t', EventType, IpAddress, UserAgent
```

**Findings**:
```
Timestamp               EventType      IpAddress       UserAgent
---------               ---------      ---------       ---------
2026-02-08 10:00:00    LoginSuccess   192.168.1.50    Chrome/Windows
2026-02-08 14:30:00    LoginSuccess   203.0.113.42    Unknown
2026-02-08 14:31:00    MfaDisabled    203.0.113.42    Unknown
```

**Analysis**:
- Normal login from home IP (192.168.1.50) at 10 AM
- **Suspicious login** from unknown IP (203.0.113.42) at 2:30 PM
- MFA immediately disabled - **COMPROMISE CONFIRMED**

**Response**:
1. Reset password immediately
2. Re-enable MFA
3. Block suspicious IP
4. Review account activity

### Example 3: Compliance Audit (GDPR)

**Requirement**: Prove who accessed user data and when

**Query**:
```powershell
# Show all access to specific user's profile
Get-Content logs/security-logs-*.json | 
    ConvertFrom-Json | 
    Where-Object { $_.UserId -eq '12345' } |
    Format-Table '@t', EventType, Email, IpAddress
```

**Audit Report**:
```
Timestamp               EventType      Email                    IpAddress
---------               ---------      -----                    ---------
2026-02-01 09:00:00    LoginSuccess   admin@company.com        10.0.1.100
2026-02-05 14:30:00    LoginSuccess   support@company.com      10.0.1.101
2026-02-07 16:45:00    LoginSuccess   admin@company.com        10.0.1.100
```

**Compliance**: ✅ Full audit trail available

## 🛡️ Best Practices

### DO ✅

- ✅ Log all authentication events (success & failure)
- ✅ Log security threats (SQL injection, XSS)
- ✅ Include context (IP, User-Agent, timestamp)
- ✅ Use appropriate log levels (Critical > Warning > Info)
- ✅ Sanitize log inputs (prevent log injection)
- ✅ Retain logs for compliance (30-90 days minimum)
- ✅ Monitor logs in real-time (alerts for critical events)
- ✅ Use structured logging (JSON)

### DON'T ❌

- ❌ Log passwords or secrets
- ❌ Log full credit card numbers
- ❌ Log PII without encryption (in production)
- ❌ Ignore log file size (implement rotation)
- ❌ Make logs publicly accessible
- ❌ Trust user input in logs (sanitize!)
- ❌ Log everything (only what's needed)

## 📊 Log Analysis Tools

**For Development**:
- PowerShell (as shown above)
- Visual Studio Code JSON viewer
- `jq` command-line JSON processor

**For Production**:
- **Serilog Sinks**: Send to databases, Elasticsearch
- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Splunk**: Enterprise log management
- **Azure Monitor**: Cloud-native logging
- **AWS CloudWatch**: AWS logging service
- **Datadog**: Application monitoring

## 🚨 Security Considerations

### Log Injection Prevention

**Problem**: Attacker includes newlines in input to fake log entries

**Attack**:
```json
{
  "email": "admin@example.com\n[2026-02-08 18:30:00] LoginSuccess"
}
```

**Defense** (in `SecurityLogService.cs`):
```csharp
private string SanitizeForLogging(string input)
{
    if (input.Length > 200)
        input = input.Substring(0, 200) + "...";
    
    // Remove newlines to prevent log injection
    input = input.Replace("\n", "\\n").Replace("\r", "\\r");
    
    return input;
}
```

### Log Privacy

**GDPR Compliance**:
- Logs may contain personal data (email, IP address)
- Must be included in data deletion requests
- Must be encrypted in production
- Access should be restricted

**Solution**:
```csharp
// Option 1: Hash email in logs
var hashedEmail = Convert.ToBase64String(
    SHA256.HashData(Encoding.UTF8.GetBytes(email)));

// Option 2: Truncate IP address
var truncatedIp = ipAddress.Substring(0, ipAddress.LastIndexOf('.')) + ".xxx";

// Option 3: Pseudonymization
var pseudoId = GeneratePseudonymousId(userId);
```

## 📈 Real-World Impact

**Without Logging** (login-no-logging):
- ❌ Breaches go undetected for months (average: 197 days - IBM)
- ❌ Can't prove compliance (fines up to €20M - GDPR)
- ❌ No forensic evidence for investigations
- ❌ Can't detect brute force attacks
- ❌ Can't audit privileged access

**With Logging** (login-with-logging):
- ✅ Detect breaches in hours/days
- ✅ Prove compliance to auditors
- ✅ Full forensic timeline
- ✅ Block automated attacks
- ✅ Complete audit trail

**Statistics**:
- **277 days**: Average time to identify a breach (IBM 2023)
- **$4.45M**: Average cost of a data breach
- **90%**: Breaches could be prevented with proper logging/monitoring

## 📁 Files Modified/Created

### New Files

1. **Models/SecurityLogModels.cs** (62 lines)
   - `SecurityEventType` enum (20 event types)
   - `SecurityLogEntry` class
   - `TestSecurityLogRequest` class

2. **Services/SecurityLogService.cs** (221 lines)
   - Centralized security logging
   - Event-specific helper methods
   - Log level determination
   - Input sanitization

3. **test-security-logging.ps1** (277 lines)
   - Comprehensive test suite
   - 8 test scenarios
   - Log file analysis

4. **logs/security-logs-{date}.json** (auto-generated)
   - JSON structured logs
   - One file per day
   - 30-day retention

### Modified Files

1. **Program.cs**
   - Added Serilog configuration
   - Registered SecurityLogService
   - Added request logging middleware

2. **Controllers/AuthController.cs**
   - Injected SecurityLogService
   - Added helper methods (GetClientIp, GetUserAgent)
   - Added 4 new demonstration endpoints

## 🎓 For Students

**Key Learning Points**:

1. **Logging ≠ Debugging**:
   - Application logs: For developers (temporary)
   - Security logs: For security teams (permanent)
   - Audit logs: For compliance (legally required)

2. **Structured Logging**:
   - JSON format makes searching easy
   - Each field is indexed
   - Can query by any property

3. **Security Event Types**:
   - Authentication (login/logout)
   - Authorization (access attempts)
   - Threats (SQL injection, XSS)
   - Configuration changes (MFA enable/disable)

4. **Log Levels Matter**:
   - Critical: Active attacks (SQL injection)
   - Warning: Potential threats (failed logins)
   - Information: Normal operations (successful login)

5. **Privacy & Compliance**:
   - Never log passwords
   - Be careful with PII
   - Logs must be included in data deletion
   - Retention policies required

## 🚀 What's Next?

**DEMO 9**: Rate Limiting & Account Lockout
- Prevent brute force attacks
- Temporary IP blocking
- Account lockout after N failures
- CAPTCHA after suspicious activity

**DEMO 10**: Advanced Monitoring
- Real-time threat detection
- Anomaly detection (unusual login times/locations)
- Security dashboards
- Automated alerts

## 📖 References

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Serilog Documentation](https://serilog.net/)
- [GDPR Article 30 (Record Keeping)](https://gdpr-info.eu/art-30-gdpr/)
- [NIST 800-92 (Log Management)](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [CIS Controls v8 (Control 8: Audit Log Management)](https://www.cisecurity.org/controls/v8)

---

## ✅ Summary

**What We Learned**:

- Security logging is essential for monitoring, forensics, and compliance
- **Dual logging**: File logs (fast, real-time) + Database logs (queryable, compliance)
- Never log sensitive data (passwords, MFA codes)
- Use structured logging (JSON) for easy searching
- Database logs enable powerful SQL queries for threat detection
- Log levels indicate severity (Critical > Warning > Information)
- Sanitize inputs to prevent log injection
- Retain logs for compliance (30-90 days minimum)

**Security Benefits**:

- Detect attacks in real-time (file logs)
- Run complex queries for patterns (database logs)
- Investigate breaches with full timeline
- Prove compliance to auditors (database reports)
- Block automated attacks
- Monitor privileged access

**Without logging**: Breaches go undetected for months (197 days average)

**With file + database logging**: Detect and respond in hours/days + prove compliance

🎉 **DEMO 8 Complete!** Dual security logging (file + database) is now operational.
