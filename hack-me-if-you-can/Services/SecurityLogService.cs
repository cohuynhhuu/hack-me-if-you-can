using Microsoft.Extensions.Logging;
using HackMeIfYouCan.Models;
using PasswordSecurityDemo.Data;
using PasswordSecurityDemo.Models;

namespace HackMeIfYouCan.Services;

/// <summary>
/// STEP 8: Centralized Security Logging Service
/// 
/// WHY THIS MATTERS:
/// - Security logs are NOT for debugging - they're for:
///   1. Incident Response: Detect and investigate breaches
///   2. Forensics: Understand what happened during an attack
///   3. Compliance: Meet regulatory requirements (GDPR, SOC 2, PCI-DSS)
///   4. Threat Detection: Identify patterns of malicious activity
/// 
/// WHAT WE LOG:
/// - Authentication events (success/failure)
/// - Security threats (SQL injection, XSS)
/// - Authorization failures
/// - MFA events
/// 
/// WHERE WE LOG:
/// - File: JSON structured logs (Serilog)
/// - Database: SQL Server table for long-term retention and compliance
/// 
/// WHAT WE DON'T LOG:
/// - Passwords (NEVER)
/// - MFA codes/secrets
/// - Sensitive user data
/// </summary>
public class SecurityLogService
{
    private readonly ILogger<SecurityLogService> _logger;
    private readonly AppDbContext _context;

    public SecurityLogService(ILogger<SecurityLogService> logger, AppDbContext context)
    {
        _logger = logger;
        _context = context;
    }

    /// <summary>
    /// Log a security event with full context
    /// Writes to BOTH file logs (JSON) and database
    /// </summary>
    public async Task LogSecurityEvent(SecurityLogEntry entry)
    {
        var logLevel = DetermineLogLevel(entry.EventType);
        
        // 1. Write to file logs (Serilog - JSON)
        _logger.Log(logLevel,
            "SecurityEvent: {EventType} | User: {Email} ({UserId}) | IP: {IpAddress} | {Message}",
            entry.EventType,
            entry.Email ?? "anonymous",
            entry.UserId ?? "N/A",
            entry.IpAddress,
            entry.Message);
        
        // Log additional context if provided
        if (entry.AdditionalData != null && entry.AdditionalData.Count > 0)
        {
            _logger.Log(logLevel, "Additional Data: {@AdditionalData}", entry.AdditionalData);
        }

        // 2. Write to database (SQL Server)
        try
        {
            var dbLog = new SecurityLog
            {
                Timestamp = entry.Timestamp,
                EventType = entry.EventType.ToString(),
                UserId = entry.UserId,
                Email = entry.Email,
                IpAddress = entry.IpAddress,
                UserAgent = entry.UserAgent,
                Message = entry.Message,
                LogLevel = logLevel.ToString(),
                AdditionalData = entry.AdditionalData
            };

            _context.SecurityLogs.Add(dbLog);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            // Don't fail the request if logging fails
            _logger.LogError(ex, "Failed to write security log to database");
        }
    }

    /// <summary>
    /// Helper: Log login success
    /// </summary>
    public async Task LogLoginSuccess(string email, string userId, string ipAddress, string userAgent, bool mfaUsed = false)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.LoginSuccess,
            Email = email,
            UserId = userId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = mfaUsed ? "User logged in with MFA" : "User logged in without MFA",
            AdditionalData = new Dictionary<string, object>
            {
                ["MfaUsed"] = mfaUsed
            }
        });
    }

    /// <summary>
    /// Helper: Log login failure
    /// </summary>
    public async Task LogLoginFailure(string email, string ipAddress, string userAgent, string reason)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.LoginFailure,
            Email = email,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = $"Login failed: {reason}"
        });
    }

    /// <summary>
    /// Helper: Log SQL injection attempt
    /// </summary>
    public async Task LogSqlInjectionAttempt(string input, string ipAddress, string userAgent)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.SqlInjectionAttempt,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = "SQL injection attempt detected",
            AdditionalData = new Dictionary<string, object>
            {
                ["SuspiciousInput"] = SanitizeForLogging(input)
            }
        });
    }

    /// <summary>
    /// Helper: Log XSS attempt
    /// </summary>
    public async Task LogXssAttempt(string input, string ipAddress, string userAgent)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.XssAttemptDetected,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = "XSS payload detected",
            AdditionalData = new Dictionary<string, object>
            {
                ["SuspiciousInput"] = SanitizeForLogging(input)
            }
        });
    }

    /// <summary>
    /// Helper: Log invalid CAPTCHA
    /// </summary>
    public async Task LogInvalidCaptcha(string email, string ipAddress, string userAgent)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.InvalidCaptcha,
            Email = email,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = "Invalid CAPTCHA attempt"
        });
    }

    /// <summary>
    /// Helper: Log JWT validation failure
    /// </summary>
    public async Task LogJwtValidationFailure(string ipAddress, string userAgent, string reason)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.JwtValidationFailure,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = $"JWT validation failed: {reason}"
        });
    }

    /// <summary>
    /// Helper: Log MFA events
    /// </summary>
    public async Task LogMfaEvent(SecurityEventType eventType, string email, string userId, string ipAddress, string userAgent, string? message = null)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = eventType,
            Email = email,
            UserId = userId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = message ?? eventType.ToString()
        });
    }

    /// <summary>
    /// Helper: Log unauthorized access
    /// </summary>
    public async Task LogUnauthorizedAccess(string resource, string ipAddress, string userAgent)
    {
        await LogSecurityEvent(new SecurityLogEntry
        {
            EventType = SecurityEventType.UnauthorizedAccess,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Message = $"Unauthorized access attempt to: {resource}"
        });
    }

    /// <summary>
    /// Determine appropriate log level based on event type
    /// </summary>
    private LogLevel DetermineLogLevel(SecurityEventType eventType)
    {
        return eventType switch
        {
            // Critical security threats
            SecurityEventType.SqlInjectionAttempt => LogLevel.Critical,
            SecurityEventType.XssAttemptDetected => LogLevel.Critical,
            SecurityEventType.UnauthorizedAccess => LogLevel.Warning,
            
            // Authentication failures
            SecurityEventType.LoginFailure => LogLevel.Warning,
            SecurityEventType.InvalidPassword => LogLevel.Warning,
            SecurityEventType.MfaFailure => LogLevel.Warning,
            SecurityEventType.InvalidCaptcha => LogLevel.Warning,
            
            // JWT issues
            SecurityEventType.JwtValidationFailure => LogLevel.Warning,
            SecurityEventType.JwtExpired => LogLevel.Information,
            SecurityEventType.JwtInvalidSignature => LogLevel.Warning,
            
            // Successful events
            SecurityEventType.LoginSuccess => LogLevel.Information,
            SecurityEventType.MfaSuccess => LogLevel.Information,
            SecurityEventType.MfaEnabled => LogLevel.Information,
            SecurityEventType.MfaDisabled => LogLevel.Information,
            SecurityEventType.AccountCreated => LogLevel.Information,
            
            _ => LogLevel.Information
        };
    }

    /// <summary>
    /// Sanitize input for safe logging (prevent log injection)
    /// </summary>
    private string SanitizeForLogging(string input)
    {
        // Truncate long inputs
        if (input.Length > 200)
        {
            input = input.Substring(0, 200) + "...";
        }
        
        // Remove newlines to prevent log injection
        input = input.Replace("\n", "\\n").Replace("\r", "\\r");
        
        return input;
    }
}
