using OtpNet;
using QRCoder;
using System.Text;

namespace PasswordSecurityDemo.Services;

public interface IMfaService
{
    string GenerateSecret();
    string GenerateQrCodeDataUrl(string email, string secret, string issuer = "PasswordSecurityDemo");
    bool VerifyTotp(string secret, string userProvidedCode);
}

public class MfaService : IMfaService
{
    private readonly ILogger<MfaService> _logger;
    private const int TotpCodeLength = 6;
    private const int TimeStepSeconds = 30; // Standard TOTP time step

    public MfaService(ILogger<MfaService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Generates a random Base32-encoded secret for TOTP
    /// </summary>
    /// <returns>Base32-encoded secret string</returns>
    public string GenerateSecret()
    {
        // Generate a 20-byte (160-bit) random secret - recommended by RFC 6238
        var secretBytes = new byte[20];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(secretBytes);
        }

        // Encode as Base32 (required format for TOTP)
        var secret = Base32Encoding.ToString(secretBytes);
        
        _logger.LogInformation("Generated new TOTP secret (length: {Length})", secret.Length);
        
        return secret;
    }

    /// <summary>
    /// Generates a QR code data URL for Google Authenticator
    /// Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
    /// </summary>
    /// <param name="email">User's email address</param>
    /// <param name="secret">Base32-encoded TOTP secret</param>
    /// <param name="issuer">App name shown in authenticator</param>
    /// <returns>QR code as base64-encoded PNG data URL</returns>
    public string GenerateQrCodeDataUrl(string email, string secret, string issuer = "PasswordSecurityDemo")
    {
        // Construct otpauth URI according to Google Authenticator spec
        // Format: otpauth://totp/ISSUER:EMAIL?secret=SECRET&issuer=ISSUER
        var otpAuthUrl = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";

        _logger.LogInformation("Generated OTP Auth URL for {Email}", email);

        // Generate QR code from otpauth URL
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(otpAuthUrl, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrCodeBytes = qrCode.GetGraphic(20); // 20 pixels per module

        // Convert to base64 data URL for easy embedding in HTML/JSON
        var qrCodeBase64 = Convert.ToBase64String(qrCodeBytes);
        var dataUrl = $"data:image/png;base64,{qrCodeBase64}";

        return dataUrl;
    }

    /// <summary>
    /// Verifies a TOTP code provided by the user
    /// </summary>
    /// <param name="secret">User's Base32-encoded TOTP secret</param>
    /// <param name="userProvidedCode">6-digit code from authenticator app</param>
    /// <returns>True if code is valid, false otherwise</returns>
    public bool VerifyTotp(string secret, string userProvidedCode)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            _logger.LogWarning("TOTP verification failed: secret is null or empty");
            return false;
        }

        if (string.IsNullOrWhiteSpace(userProvidedCode))
        {
            _logger.LogWarning("TOTP verification failed: user code is null or empty");
            return false;
        }

        // Remove any spaces or formatting from user input
        userProvidedCode = userProvidedCode.Replace(" ", "").Replace("-", "").Trim();

        // Validate code format
        if (userProvidedCode.Length != TotpCodeLength || !userProvidedCode.All(char.IsDigit))
        {
            _logger.LogWarning("TOTP verification failed: invalid code format (expected {ExpectedLength} digits, got '{Code}')", 
                TotpCodeLength, userProvidedCode);
            return false;
        }

        try
        {
            // Decode Base32 secret
            var secretBytes = Base32Encoding.ToBytes(secret);

            // Create TOTP instance
            var totp = new Totp(secretBytes, step: TimeStepSeconds);

            // Verify code with time window tolerance (allows 1 step before/after for clock drift)
            // This gives ~90 seconds window total (30s before, current 30s, 30s after)
            var verificationWindow = new VerificationWindow(previous: 1, future: 1);
            
            long timeStepMatched;
            var isValid = totp.VerifyTotp(userProvidedCode, out timeStepMatched, verificationWindow);

            if (isValid)
            {
                _logger.LogInformation("TOTP verification SUCCESS - code matched at time step {TimeStep}", timeStepMatched);
            }
            else
            {
                _logger.LogWarning("TOTP verification FAILED - code did not match");
            }

            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TOTP verification failed with exception");
            return false;
        }
    }

    /// <summary>
    /// Generates the current TOTP code for testing/debugging purposes
    /// WARNING: This should only be used in development/testing
    /// </summary>
    /// <param name="secret">Base32-encoded TOTP secret</param>
    /// <returns>Current 6-digit TOTP code</returns>
    public string GetCurrentTotp(string secret)
    {
        var secretBytes = Base32Encoding.ToBytes(secret);
        var totp = new Totp(secretBytes, step: TimeStepSeconds);
        var code = totp.ComputeTotp(DateTime.UtcNow);
        
        _logger.LogWarning("Generated current TOTP code for testing (code: {Code})", code);
        
        return code;
    }
}
