namespace PasswordSecurityDemo.Models;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    
    // BAD: Storing password in plain text - visible to anyone with DB access
    public string? Password { get; set; }
    
    // GOOD: Storing hashed password - irreversible, includes salt
    public string? PasswordHash { get; set; }
    
    // STEP 7: Multi-Factor Authentication (TOTP)
    public bool MfaEnabled { get; set; } = false;
    public string? MfaSecret { get; set; }  // Base32-encoded secret for TOTP
    
    // Audit field
    public DateTime CreatedAt { get; set; }
}
