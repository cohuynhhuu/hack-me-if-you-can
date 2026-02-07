using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PasswordSecurityDemo.Data;
using HackMeIfYouCan.Services;
using HackMeIfYouCan.Models;
using Serilog;

namespace PasswordSecurityDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class LogsController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly SecurityLogService _securityLog;

    public LogsController(AppDbContext context, SecurityLogService securityLog)
    {
        _context = context;
        _securityLog = securityLog;
    }

    /// <summary>
    /// Get security logs with optional filters
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetLogs(
        [FromQuery] string? eventType = null,
        [FromQuery] string? level = null,
        [FromQuery] int limit = 100)
    {
        try
        {
            var query = _context.SecurityLogs.AsQueryable();

            // Apply filters
            if (!string.IsNullOrEmpty(eventType))
            {
                query = query.Where(l => l.EventType == eventType);
            }

            if (!string.IsNullOrEmpty(level))
            {
                query = query.Where(l => l.LogLevel == level);
            }

            // Get logs ordered by timestamp descending, limit results
            var logs = await query
                .OrderByDescending(l => l.Timestamp)
                .Take(limit)
                .Select(l => new
                {
                    l.Id,
                    l.Timestamp,
                    Level = l.LogLevel,
                    l.Message,
                    l.EventType,
                    l.UserId,
                    l.IpAddress,
                    AdditionalData = l.AdditionalDataJson
                })
                .ToListAsync();

            return Ok(logs);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve security logs");
            return StatusCode(500, new { error = "Failed to retrieve logs", details = ex.Message });
        }
    }

    /// <summary>
    /// Generate test security logs for demonstration
    /// </summary>
    [HttpPost("generate-test")]
    public async Task<IActionResult> GenerateTestLogs()
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

            // Generate various test log entries using SecurityLogService
            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.LoginSuccess,
                UserId = "test-user-123",
                IpAddress = "192.168.1.100",
                Message = "Test: User login successful"
            });

            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.LoginFailure,
                UserId = "hacker@evil.com",
                IpAddress = "10.0.0.666",
                Message = "Test: Failed login attempt"
            });

            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.RateLimitExceeded,
                IpAddress = "192.168.1.200",
                Message = "Test: Rate limit exceeded",
                AdditionalData = new Dictionary<string, object> { { "Endpoint", "/api/data" } }
            });

            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.SqlInjectionDetected,
                IpAddress = "10.0.0.666",
                Message = "Test: SQL Injection attempt detected",
                AdditionalData = new Dictionary<string, object> { { "Input", "' OR '1'='1" } }
            });

            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.XssAttemptDetected,
                IpAddress = "10.0.0.666",
                Message = "Test: XSS attempt blocked",
                AdditionalData = new Dictionary<string, object> { { "Input", "<script>alert('XSS')</script>" } }
            });

            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.ValidationSuccess,
                UserId = "valid-user-456",
                IpAddress = ipAddress,
                Message = "Test: Input validation passed"
            });

            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.UnauthorizedAccess,
                IpAddress = "10.0.0.666",
                Message = "Test: Critical security event - Multiple failed auth attempts",
                AdditionalData = new Dictionary<string, object> { { "Count", 10 } }
            });

            return Ok(new { message = "Test logs generated successfully", count = 7 });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to generate test logs");
            return StatusCode(500, new { error = "Failed to generate test logs" });
        }
    }
}
