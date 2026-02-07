using System.ComponentModel.DataAnnotations;

namespace PasswordSecurityDemo.Models;

/// <summary>
/// STEP 5: Login request with CAPTCHA token
/// Used to demonstrate bot protection
/// </summary>
public class LoginWithCaptchaRequest
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "CAPTCHA token is required")]
    public string CaptchaToken { get; set; } = string.Empty;
}

/// <summary>
/// STEP 5: Registration request with CAPTCHA token
/// Used to demonstrate bot protection on registration
/// </summary>
public class RegisterWithCaptchaRequest
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [MaxLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
    [MaxLength(100, ErrorMessage = "Password cannot exceed 100 characters")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "CAPTCHA token is required")]
    public string CaptchaToken { get; set; } = string.Empty;
}
