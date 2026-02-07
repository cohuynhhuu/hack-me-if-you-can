namespace HackMeIfYouCan.Models;

/// <summary>
/// Types of security events that should be logged
/// </summary>
public enum SecurityEventType
{
    // Authentication Events
    LoginSuccess,
    LoginFailure,
    InvalidPassword,
    
    // MFA Events
    MfaEnabled,
    MfaDisabled,
    MfaSuccess,
    MfaFailure,
    
    // Security Threats
    SqlInjectionAttempt,
    SqlInjectionDetected, // Alias for SqlInjectionAttempt
    XssAttemptDetected,
    InvalidCaptcha,
    RateLimitExceeded,
    ValidationSuccess,
    ValidationFailure,
    
    // JWT Events
    JwtValidationFailure,
    JwtExpired,
    JwtInvalidSignature,
    
    // Authorization Events
    UnauthorizedAccess,
    ForbiddenAccess,
    
    // Account Events
    AccountCreated,
    AccountDeleted,
    PasswordChanged
}

/// <summary>
/// Security log entry with all relevant context
/// </summary>
public class SecurityLogEntry
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public SecurityEventType EventType { get; set; }
    public string? UserId { get; set; }
    public string? Email { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, object>? AdditionalData { get; set; }
}

/// <summary>
/// Test request for security logging demonstrations
/// </summary>
public class TestSecurityLogRequest
{
    public string Input { get; set; } = string.Empty;
}
