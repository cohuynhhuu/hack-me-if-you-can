using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using HackMeIfYouCan.Models;

namespace PasswordSecurityDemo.Models;

/// <summary>
/// STEP 8: Database entity for security audit logs
/// Stores security events in SQL Server for long-term retention and compliance
/// </summary>
public class SecurityLog
{
    [Key]
    public int Id { get; set; }

    [Required]
    public DateTime Timestamp { get; set; }

    [Required]
    [MaxLength(50)]
    public string EventType { get; set; } = string.Empty;

    [MaxLength(450)]
    public string? UserId { get; set; }

    [MaxLength(256)]
    public string? Email { get; set; }

    [Required]
    [MaxLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    [MaxLength(500)]
    public string UserAgent { get; set; } = string.Empty;

    [Required]
    [MaxLength(500)]
    public string Message { get; set; } = string.Empty;

    [MaxLength(20)]
    public string LogLevel { get; set; } = "Information";

    /// <summary>
    /// Additional data stored as JSON
    /// </summary>
    public string? AdditionalDataJson { get; set; }

    /// <summary>
    /// Not mapped - used for deserialization
    /// </summary>
    [NotMapped]
    public Dictionary<string, object>? AdditionalData
    {
        get
        {
            if (string.IsNullOrEmpty(AdditionalDataJson))
                return null;
            return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(AdditionalDataJson);
        }
        set
        {
            if (value == null)
                AdditionalDataJson = null;
            else
                AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(value);
        }
    }
}
