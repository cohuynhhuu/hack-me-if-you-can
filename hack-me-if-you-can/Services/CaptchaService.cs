namespace PasswordSecurityDemo.Services;

/// <summary>
/// Service for verifying Google reCAPTCHA tokens
/// Implements server-side CAPTCHA validation to prevent bot attacks
/// </summary>
public interface ICaptchaService
{
    Task<CaptchaVerificationResult> VerifyAsync(string token, string? remoteIp = null);
}

public class CaptchaService : ICaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<CaptchaService> _logger;
    private const string GoogleVerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

    public CaptchaService(
        HttpClient httpClient,
        IConfiguration configuration,
        ILogger<CaptchaService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<CaptchaVerificationResult> VerifyAsync(string token, string? remoteIp = null)
    {
        var secretKey = _configuration["ReCaptcha:SecretKey"];
        
        if (string.IsNullOrEmpty(secretKey))
        {
            _logger.LogError("reCAPTCHA secret key not configured");
            return new CaptchaVerificationResult
            {
                Success = false,
                ErrorCodes = new[] { "missing-secret-key" }
            };
        }

        if (string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("CAPTCHA token is empty");
            return new CaptchaVerificationResult
            {
                Success = false,
                ErrorCodes = new[] { "missing-input-response" }
            };
        }

        try
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("secret", secretKey),
                new KeyValuePair<string, string>("response", token),
                new KeyValuePair<string, string>("remoteip", remoteIp ?? string.Empty)
            });

            var response = await _httpClient.PostAsync(GoogleVerifyUrl, content);
            var jsonResponse = await response.Content.ReadAsStringAsync();

            var result = System.Text.Json.JsonSerializer.Deserialize<CaptchaVerificationResult>(
                jsonResponse,
                new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

            if (result == null)
            {
                _logger.LogError("Failed to deserialize CAPTCHA response");
                return new CaptchaVerificationResult
                {
                    Success = false,
                    ErrorCodes = new[] { "deserialization-error" }
                };
            }

            if (result.Success)
            {
                _logger.LogInformation("CAPTCHA verification successful. Score: {Score}", result.Score);
            }
            else
            {
                _logger.LogWarning("CAPTCHA verification failed. Errors: {Errors}", 
                    string.Join(", ", result.ErrorCodes ?? Array.Empty<string>()));
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying CAPTCHA token");
            return new CaptchaVerificationResult
            {
                Success = false,
                ErrorCodes = new[] { "verification-error" }
            };
        }
    }
}

/// <summary>
/// Response from Google reCAPTCHA verification API
/// </summary>
public class CaptchaVerificationResult
{
    /// <summary>
    /// Whether the CAPTCHA was successfully verified
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Timestamp of the challenge (ISO format)
    /// </summary>
    public string? ChallengeTs { get; set; }

    /// <summary>
    /// Hostname of the site where the CAPTCHA was solved
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// Score for reCAPTCHA v3 (0.0 - 1.0, higher is more human-like)
    /// </summary>
    public double? Score { get; set; }

    /// <summary>
    /// Action name for reCAPTCHA v3
    /// </summary>
    public string? Action { get; set; }

    /// <summary>
    /// Error codes if verification failed
    /// </summary>
    public string[]? ErrorCodes { get; set; }

    /// <summary>
    /// Error codes property name variant (for JSON deserialization)
    /// </summary>
    public string[]? ErrorCodess
    {
        get => ErrorCodes;
        set => ErrorCodes = value;
    }
}
