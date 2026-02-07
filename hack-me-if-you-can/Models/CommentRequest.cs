using System.ComponentModel.DataAnnotations;

namespace PasswordSecurityDemo.Models;

/// <summary>
/// STEP 4: Request model for comments/user input
/// Used to demonstrate XSS prevention
/// </summary>
public class CommentRequest
{
    [Required(ErrorMessage = "Content is required")]
    [MaxLength(1000, ErrorMessage = "Content cannot exceed 1000 characters")]
    public string Content { get; set; } = string.Empty;
}
