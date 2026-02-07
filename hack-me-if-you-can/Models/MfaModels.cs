using System.ComponentModel.DataAnnotations;

namespace PasswordSecurityDemo.Models;

/// <summary>
/// Request to enable MFA for a user
/// </summary>
public class EnableMfaRequest
{
    [Required(ErrorMessage = "User ID is required")]
    public int UserId { get; set; }
}

/// <summary>
/// Response after enabling MFA - includes QR code for setup
/// </summary>
public class EnableMfaResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Secret { get; set; }  // Base32 secret (backup)
    public string? QrCodeDataUrl { get; set; }  // QR code for scanning
    public List<string>? Instructions { get; set; }  // Setup instructions
}

/// <summary>
/// Request to confirm MFA setup by verifying first code
/// </summary>
public class ConfirmMfaRequest
{
    [Required(ErrorMessage = "User ID is required")]
    public int UserId { get; set; }

    [Required(ErrorMessage = "Verification code is required")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be exactly 6 digits")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits")]
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// Request to disable MFA
/// </summary>
public class DisableMfaRequest
{
    [Required(ErrorMessage = "User ID is required")]
    public int UserId { get; set; }

    [Required(ErrorMessage = "Password is required for security verification")]
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Login request with MFA code
/// </summary>
public class LoginWithMfaRequest
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "MFA code is required")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be exactly 6 digits")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits")]
    public string MfaCode { get; set; } = string.Empty;
}

/// <summary>
/// Response indicating MFA is required
/// </summary>
public class MfaRequiredResponse
{
    public bool Success { get; set; } = false;
    public string Message { get; set; } = "MFA code required";
    public bool MfaRequired { get; set; } = true;
    public string Instructions { get; set; } = "Please provide your 6-digit code from Google Authenticator";
}
