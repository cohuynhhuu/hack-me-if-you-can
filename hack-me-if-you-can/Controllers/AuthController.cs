using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using System.Security.Claims;
using System.Web;
using PasswordSecurityDemo.Data;
using PasswordSecurityDemo.Models;
using PasswordSecurityDemo.Services;
using HackMeIfYouCan.Models;
using HackMeIfYouCan.Services;

namespace PasswordSecurityDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly ILogger<AuthController> _logger;
    private readonly ICaptchaService _captchaService;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IConfiguration _configuration;
    private readonly IMfaService _mfaService;
    private readonly SecurityLogService _securityLog; // STEP 8

    public AuthController(
        AppDbContext context, 
        IPasswordHasher<User> passwordHasher,
        ILogger<AuthController> logger,
        ICaptchaService captchaService,
        IJwtTokenService jwtTokenService,
        IConfiguration configuration,
        IMfaService mfaService,
        SecurityLogService securityLog) // STEP 8
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _logger = logger;
        _captchaService = captchaService;
        _jwtTokenService = jwtTokenService;
        _configuration = configuration;
        _mfaService = mfaService;
        _securityLog = securityLog; // STEP 8
    }

    // STEP 8: Helper methods to get client context
    private string GetClientIp() => 
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    
    private string GetUserAgent() => 
        HttpContext.Request.Headers["User-Agent"].ToString() ?? "unknown";

    // ==================== BAD EXAMPLE ====================
    // NEVER DO THIS: Storing passwords in plain text
    [HttpPost("register-insecure")]
    public async Task<IActionResult> RegisterInsecure([FromBody] RegisterRequest request)
    {
        // STEP 2: Validate input with ModelState
        // [ApiController] automatically validates and returns 400 if validation fails
        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                success = false,
                message = "Validation failed",
                errors = ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
            });
        }

        // Business logic validation: Check if email already exists
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());
        
        if (existingUser != null)
        {
            _logger.LogWarning("Registration attempt with existing email: {Email}", request.Email);
            return BadRequest(new
            {
                success = false,
                message = "Email already registered",
                errors = new Dictionary<string, string[]>
                {
                    { "Email", new[] { "This email is already registered" } }
                }
            });
        }

        var user = new User
        {
            Email = request.Email.ToLower().Trim(),
            Password = request.Password,  // DANGER: Plain text password stored directly!
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User registered INSECURELY: {Email}", user.Email);

        return Ok(new
        {
            success = true,
            message = "User registered INSECURELY",
            userId = user.Id,
            warning = "⚠️ Password stored in plain text - anyone with DB access can see it!"
        });
    }

    // ==================== GOOD EXAMPLE ====================
    // Use password hashing with automatic salt generation
    [HttpPost("register-secure")]
    public async Task<IActionResult> RegisterSecure([FromBody] RegisterRequest request)
    {
        // STEP 2: Validate input with ModelState
        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                success = false,
                message = "Validation failed",
                errors = ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
            });
        }

        // Business logic validation: Check if email already exists
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());
        
        if (existingUser != null)
        {
            _logger.LogWarning("Registration attempt with existing email: {Email}", request.Email);
            return BadRequest(new
            {
                success = false,
                message = "Email already registered",
                errors = new Dictionary<string, string[]>
                {
                    { "Email", new[] { "This email is already registered" } }
                }
            });
        }

        var user = new User
        {
            Email = request.Email.ToLower().Trim(),
            CreatedAt = DateTime.UtcNow
        };

        // PasswordHasher automatically:
        // 1. Generates a unique random salt
        // 2. Combines salt + password
        // 3. Applies PBKDF2 hashing algorithm (industry standard)
        // 4. Returns hash that includes salt (no need to store separately)
        user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User registered SECURELY: {Email}", user.Email);

        return Ok(new
        {
            success = true,
            message = "User registered SECURELY",
            userId = user.Id,
            info = "✅ Password hashed with salt - irreversible and unique per user"
        });
    }

    // ==================== LOGIN WITH VERIFICATION ====================
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // STEP 2: Validate input
        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                success = false,
                message = "Validation failed",
                errors = ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
            });
        }

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());
        
        if (user == null)
        {
            _logger.LogWarning("Login attempt with non-existent email: {Email}", request.Email);
            return Unauthorized(new { success = false, message = "Invalid credentials" });
        }

        // If user registered insecurely (plain text password)
        if (!string.IsNullOrEmpty(user.Password))
        {
            if (user.Password == request.Password)
            {
                _logger.LogWarning("Insecure login successful for: {Email}", user.Email);
                return Ok(new
                {
                    success = true,
                    message = "Login successful (INSECURE method)",
                    warning = "⚠️ This account uses plain-text password storage!"
                });
            }
        }

        // If user registered securely (hashed password)
        if (!string.IsNullOrEmpty(user.PasswordHash))
        {
            // VerifyHashedPassword compares the hash of provided password
            // with stored hash - returns Success, Failed, or SuccessRehashNeeded
            var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            
            if (result == PasswordVerificationResult.Success || 
                result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                _logger.LogInformation("Secure login successful for: {Email}", user.Email);
                return Ok(new
                {
                    success = true,
                    message = "Login successful (SECURE method)",
                    info = "✅ Password verified using secure hashing"
                });
            }
        }

        _logger.LogWarning("Failed login attempt for: {Email}", request.Email);
        return Unauthorized(new { success = false, message = "Invalid credentials" });
    }

    // ==================== HELPER ENDPOINT ====================
    // View all users (for demo purposes only - NEVER do this in production!)
    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users
            .Select(u => new
            {
                u.Id,
                u.Email,
                PlainPassword = u.Password ?? "N/A",
                PasswordHash = u.PasswordHash ?? "N/A",
                HashLength = (u.PasswordHash ?? "").Length
            })
            .ToListAsync();

        return Ok(users);
    }

    // ==================== STEP 3: SQL INJECTION DEMO ====================

    /// <summary>
    /// VULNERABLE: Login using raw SQL with string concatenation
    /// DANGER: Susceptible to SQL Injection attacks!
    /// </summary>
    [HttpPost("login-vulnerable")]
    public async Task<IActionResult> LoginVulnerable([FromQuery] string email, [FromQuery] string password)
    {
        _logger.LogWarning("⚠️ VULNERABLE ENDPOINT CALLED: login-vulnerable");

        try
        {
            // DANGER: String concatenation creates SQL Injection vulnerability!
            var sql = $"SELECT * FROM Users WHERE Email = '{email}' AND Password = '{password}'";
            
            _logger.LogWarning("Executing VULNERABLE SQL: {Sql}", sql);

            // Execute raw SQL query
            var users = await _context.Users
                .FromSqlRaw(sql)
                .ToListAsync();

            if (users.Any())
            {
                var user = users.First();
                return Ok(new
                {
                    success = true,
                    message = "Login successful (VULNERABLE method)",
                    warning = "⚠️ This endpoint is vulnerable to SQL Injection!",
                    user = new { user.Id, user.Email },
                    sqlExecuted = sql
                });
            }

            return Unauthorized(new 
            { 
                success = false, 
                message = "Invalid credentials",
                sqlExecuted = sql
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SQL Injection attack detected or SQL error");
            return StatusCode(500, new
            {
                success = false,
                message = "Database error occurred",
                error = ex.Message,
                warning = "⚠️ This might be a SQL Injection attempt!"
            });
        }
    }

    /// <summary>
    /// SECURE: Login using Entity Framework LINQ
    /// SAFE: Parameters prevent SQL Injection
    /// </summary>
    [HttpPost("login-secure")]
    public async Task<IActionResult> LoginSecure([FromBody] LoginRequest request)
    {
        _logger.LogInformation("✅ SECURE ENDPOINT CALLED: login-secure");

        if (!ModelState.IsValid)
        {
            return BadRequest(new { success = false, message = "Validation failed" });
        }

        try
        {
            // SAFE: Entity Framework uses parameterized queries
            var user = await _context.Users
                .Where(u => u.Email.ToLower() == request.Email.ToLower())
                .Where(u => u.Password == request.Password)
                .FirstOrDefaultAsync();

            if (user != null)
            {
                return Ok(new
                {
                    success = true,
                    message = "Login successful (SECURE method)",
                    info = "✅ Entity Framework LINQ prevents SQL Injection",
                    user = new { user.Id, user.Email }
                });
            }

            return Unauthorized(new { success = false, message = "Invalid credentials" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during secure login");
            return StatusCode(500, new { success = false, message = "An error occurred" });
        }
    }

    /// <summary>
    /// VULNERABLE: Search users using raw SQL with string concatenation
    /// DANGER: Susceptible to SQL Injection attacks!
    /// </summary>
    [HttpGet("search-vulnerable")]
    public async Task<IActionResult> SearchVulnerable([FromQuery] string query)
    {
        _logger.LogWarning("⚠️ VULNERABLE ENDPOINT CALLED: search-vulnerable");

        if (string.IsNullOrWhiteSpace(query))
        {
            return BadRequest(new { success = false, message = "Query parameter is required" });
        }

        try
        {
            // DANGER: String concatenation creates SQL Injection vulnerability!
            // Using = instead of LIKE to make injection clearer
            var sql = $"SELECT Id, Email, PasswordHash FROM Users WHERE Email = '{query}'";
            
            _logger.LogWarning("Executing VULNERABLE SQL: {Sql}", sql);

            // Execute raw SQL query
            var connection = _context.Database.GetDbConnection();
            await connection.OpenAsync();

            using var command = connection.CreateCommand();
            command.CommandText = sql;

            var results = new List<object>();
            using var reader = await command.ExecuteReaderAsync();
            
            while (await reader.ReadAsync())
            {
                results.Add(new
                {
                    id = reader.GetInt32(0),
                    email = reader.GetString(1),
                    passwordHash = reader.IsDBNull(2) ? "N/A" : reader.GetString(2).Substring(0, 20) + "..."
                });
            }

            return Ok(new
            {
                success = true,
                message = "Search completed (VULNERABLE method)",
                warning = "⚠️ This endpoint is vulnerable to SQL Injection!",
                results = results,
                sqlExecuted = sql,
                totalRecords = results.Count
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SQL Injection attack detected or SQL error");
            return StatusCode(500, new
            {
                success = false,
                message = "Database error occurred",
                error = ex.Message,
                warning = "⚠️ This might be a SQL Injection attempt!"
            });
        }
    }

    /// <summary>
    /// SECURE: Search users using Entity Framework LINQ
    /// SAFE: Parameters prevent SQL Injection
    /// </summary>
    [HttpGet("search-secure")]
    public async Task<IActionResult> SearchSecure([FromQuery] string query)
    {
        _logger.LogInformation("✅ SECURE ENDPOINT CALLED: search-secure");

        if (string.IsNullOrWhiteSpace(query))
        {
            return BadRequest(new { success = false, message = "Query parameter is required" });
        }

        // Detect potential SQL injection attempts for educational purposes
        bool sqlInjectionAttempted = query.Contains("'") || query.ToLower().Contains("or ") || 
                                   query.Contains("--") || query.ToLower().Contains("union") ||
                                   query.ToLower().Contains("drop") || query.ToLower().Contains("delete");

        try
        {
            // SAFE: Entity Framework uses parameterized queries
            var users = await _context.Users
                .Where(u => u.Email.Contains(query))
                .Select(u => new
                {
                    u.Id,
                    u.Email,
                    // Don't expose password in secure demo
                    HasPassword = !string.IsNullOrEmpty(u.PasswordHash)
                })
                .ToListAsync();

            _logger.LogInformation("Secure search for '{Query}' returned {Count} results", query, users.Count);

            return Ok(new
            {
                success = true,
                message = "Search completed (SECURE method)",
                info = "✅ Entity Framework LINQ prevents SQL Injection",
                method = "Parameterized Query with Entity Framework",
                queryPattern = "context.Users.Where(u => u.Email.Contains(userInput))",
                sqlInjectionAttempted = sqlInjectionAttempted,
                protection = sqlInjectionAttempted ? 
                    "🛡️ SQL injection payload detected but safely neutralized by Entity Framework" :
                    "🔍 Normal search executed with parameterized query",
                results = users,
                educationalNote = sqlInjectionAttempted ?
                    "The malicious SQL characters in your input were treated as literal text, not SQL code. Entity Framework automatically parameterizes all user input." :
                    "Entity Framework converted your search into a safe parameterized query that prevents SQL injection."
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during secure search");
            return StatusCode(500, new { success = false, message = "An error occurred" });
        }
    }

    /// <summary>
    /// SECURE: Search using parameterized raw SQL (alternative approach)
    /// SAFE: Parameters prevent SQL Injection
    /// </summary>
    [HttpGet("search-parameterized")]
    public async Task<IActionResult> SearchParameterized([FromQuery] string query)
    {
        _logger.LogInformation("✅ SECURE ENDPOINT CALLED: search-parameterized");

        if (string.IsNullOrWhiteSpace(query))
        {
            return BadRequest(new { success = false, message = "Query parameter is required" });
        }

        try
        {
            // SAFE: Using parameterized query even with raw SQL
            var searchPattern = $"%{query}%";
            
            var users = await _context.Users
                .FromSqlRaw("SELECT * FROM Users WHERE Email LIKE {0}", searchPattern)
                .Select(u => new
                {
                    u.Id,
                    u.Email,
                    Password = u.Password ?? "N/A"
                })
                .ToListAsync();

            return Ok(new
            {
                success = true,
                message = "Search completed (PARAMETERIZED method)",
                info = "✅ Parameterized queries prevent SQL Injection",
                results = users
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during parameterized search");
            return StatusCode(500, new { success = false, message = "An error occurred" });
        }
    }

    // ==================== STEP 4: XSS (CROSS-SITE SCRIPTING) DEMO ====================
    
    /// <summary>
    /// ⚠️ VULNERABLE: Renders user input as raw HTML without encoding
    /// This demonstrates XSS vulnerability - NEVER use in production!
    /// </summary>
    [HttpGet("profile-vulnerable")]
    public IActionResult ProfileVulnerable([FromQuery] string name)
    {
        _logger.LogWarning("🚨 VULNERABLE ENDPOINT CALLED: profile-vulnerable with name={Name}", name);

        if (string.IsNullOrEmpty(name))
        {
            name = "Guest";
        }

        // ⚠️ DANGEROUS: Directly embedding user input into HTML without encoding
        // Attacker can inject <script> tags and steal cookies/tokens
        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>User Profile (VULNERABLE)</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #ffe6e6; }}
        .warning {{ color: red; font-weight: bold; }}
        .profile {{ background: white; padding: 20px; border: 2px solid red; }}
    </style>
</head>
<body>
    <h1>🚨 VULNERABLE Profile Page</h1>
    <div class='warning'>⚠️ This page is vulnerable to XSS attacks!</div>
    <div class='profile'>
        <h2>Welcome, {name}!</h2>
        <p>This is your user profile.</p>
        <p><small>Endpoint: /api/auth/profile-vulnerable?name={name}</small></p>
    </div>
    <hr>
    <p><strong>Security Issue:</strong> User input is rendered as raw HTML without encoding.</p>
    <p><strong>Attack Vector:</strong> Try: ?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
</body>
</html>";

        _logger.LogWarning("Rendered HTML with unencoded user input: {Name}", name);
        return Content(html, "text/html");
    }

    /// <summary>
    /// SECURE: Uses HTML encoding to prevent XSS attacks
    /// SAFE: All user input is encoded before rendering
    /// </summary>
    [HttpGet("profile-secure")]
    public IActionResult ProfileSecure([FromQuery] string name)
    {
        _logger.LogInformation("✅ SECURE ENDPOINT CALLED: profile-secure");

        if (string.IsNullOrEmpty(name))
        {
            name = "Guest";
        }

        // ✅ SAFE: HtmlEncode prevents script execution
        // Input: <script>alert('XSS')</script>
        // Output: &lt;script&gt;alert('XSS')&lt;/script&gt;
        var encodedName = HttpUtility.HtmlEncode(name);

        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>User Profile (SECURE)</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #e6ffe6; }}
        .success {{ color: green; font-weight: bold; }}
        .profile {{ background: white; padding: 20px; border: 2px solid green; }}
    </style>
</head>
<body>
    <h1>✅ SECURE Profile Page</h1>
    <div class='success'>✅ This page is protected against XSS attacks!</div>
    <div class='profile'>
        <h2>Welcome, {encodedName}!</h2>
        <p>This is your user profile.</p>
        <p><small>Endpoint: /api/auth/profile-secure?name={encodedName}</small></p>
    </div>
    <hr>
    <p><strong>Security:</strong> User input is HTML-encoded before rendering.</p>
    <p><strong>Protection:</strong> Scripts are displayed as text, not executed.</p>
    <p><strong>Original input:</strong> {encodedName}</p>
</body>
</html>";

        _logger.LogInformation("Rendered HTML with encoded user input");
        return Content(html, "text/html");
    }

    /// <summary>
    /// Demo endpoint that shows both vulnerable and secure rendering side-by-side
    /// </summary>
    [HttpGet("xss-demo")]
    public IActionResult XssDemo([FromQuery] string payload = "<script>alert('XSS')</script>")
    {
        var encodedPayload = HttpUtility.HtmlEncode(payload);

        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>XSS Prevention Demo</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ display: flex; gap: 20px; margin-top: 20px; }}
        .panel {{ flex: 1; padding: 20px; background: white; border-radius: 8px; }}
        .vulnerable {{ border: 3px solid red; background: #ffe6e6; }}
        .secure {{ border: 3px solid green; background: #e6ffe6; }}
        .code {{ background: #f0f0f0; padding: 10px; font-family: monospace; border-left: 4px solid #333; margin: 10px 0; }}
        h2 {{ margin-top: 0; }}
        .warning {{ color: red; font-weight: bold; }}
        .success {{ color: green; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>🛡️ XSS (Cross-Site Scripting) Prevention Demo</h1>
    
    <div class='code'>
        <strong>Test Payload:</strong> {encodedPayload}
    </div>

    <div class='container'>
        <div class='panel vulnerable'>
            <h2>🚨 VULNERABLE (Raw HTML)</h2>
            <p class='warning'>⚠️ Script will execute!</p>
            <div class='code'>
                var html = $""Welcome, {encodedPayload}!"";
            </div>
            <hr>
            <p><strong>Output:</strong></p>
            <div style='background: white; padding: 10px;'>
                Welcome, {payload}!
            </div>
        </div>

        <div class='panel secure'>
            <h2>✅ SECURE (HTML Encoded)</h2>
            <p class='success'>✅ Script rendered as text!</p>
            <div class='code'>
                var html = $""Welcome, {{HttpUtility.HtmlEncode(input)}}!"";
            </div>
            <hr>
            <p><strong>Output:</strong></p>
            <div style='background: white; padding: 10px;'>
                Welcome, {encodedPayload}!
            </div>
        </div>
    </div>

    <hr style='margin-top: 40px;'>
    
    <h3>🎯 Test Different Payloads:</h3>
    <ul>
        <li><a href='?payload=<script>alert(""XSS"")</script>'>Basic Script Alert</a></li>
        <li><a href='?payload=<img src=x onerror=alert(""XSS"")>'>Image Tag with onerror</a></li>
        <li><a href='?payload=<svg onload=alert(""XSS"")>'>SVG onload Event</a></li>
        <li><a href='?payload=<iframe src=javascript:alert(""XSS"")>'>IFrame with JavaScript</a></li>
    </ul>

    <h3>📚 Key Concepts:</h3>
    <div class='code'>
        <strong>HTML Encoding Converts:</strong><br>
        &lt; → &amp;lt;<br>
        &gt; → &amp;gt;<br>
        &quot; → &amp;quot;<br>
        &apos; → &amp;#x27;<br>
        &amp; → &amp;amp;
    </div>

    <p><strong>Why It Works:</strong> Encoded characters are displayed as text, not interpreted as HTML/JavaScript.</p>
</body>
</html>";

        return Content(html, "text/html");
    }

    /// <summary>
    /// API endpoint that returns user input in JSON (safe by default)
    /// </summary>
    [HttpPost("comment")]
    public IActionResult AddComment([FromBody] CommentRequest request)
    {
        _logger.LogInformation("Comment received: {Content}", request.Content);

        // JSON serialization automatically escapes special characters
        // This is safe by default in ASP.NET Core
        return Ok(new
        {
            success = true,
            message = "Comment added",
            comment = new
            {
                content = request.Content,
                timestamp = DateTime.UtcNow,
                warning = "JSON responses are safe by default - special chars are escaped"
            }
        });
    }

    // ==================== STEP 5: CAPTCHA PROTECTION ====================
    
    /// <summary>
    /// ⚠️ VULNERABLE: Login without CAPTCHA protection
    /// Susceptible to credential stuffing and brute-force attacks
    /// </summary>
    [HttpPost("login-no-captcha")]
    public async Task<IActionResult> LoginNoCaptcha([FromBody] LoginRequest request)
    {
        _logger.LogWarning("⚠️ VULNERABLE ENDPOINT: login-no-captcha (no bot protection)");

        if (!ModelState.IsValid)
        {
            return BadRequest(new { success = false, message = "Validation failed" });
        }

        // Simulating credential verification
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());

        if (user == null || user.PasswordHash == null)
        {
            _logger.LogWarning("Login attempt with non-existent or insecure user: {Email}", request.Email);
            return Unauthorized(new { success = false, message = "Invalid credentials" });
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

        if (result == PasswordVerificationResult.Success)
        {
            _logger.LogInformation("⚠️ VULNERABLE: Login successful without CAPTCHA check for {Email}", user.Email);
            return Ok(new
            {
                success = true,
                message = "Login successful",
                warning = "⚠️ This endpoint has NO bot protection - vulnerable to credential stuffing!",
                userId = user.Id,
                email = user.Email
            });
        }

        return Unauthorized(new { success = false, message = "Invalid credentials" });
    }

    /// <summary>
    /// ✅ SECURE: Login with CAPTCHA protection
    /// Protects against bots, credential stuffing, and brute-force attacks
    /// </summary>
    [HttpPost("login-with-captcha")]
    public async Task<IActionResult> LoginWithCaptcha([FromBody] LoginWithCaptchaRequest request)
    {
        _logger.LogInformation("✅ SECURE ENDPOINT: login-with-captcha");

        if (!ModelState.IsValid)
        {
            return BadRequest(new 
            { 
                success = false, 
                message = "Validation failed",
                errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)
            });
        }

        // STEP 1: Verify CAPTCHA token (CRITICAL - Always do this first!)
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var captchaResult = await _captchaService.VerifyAsync(request.CaptchaToken, remoteIp);

        if (!captchaResult.Success)
        {
            _logger.LogWarning("CAPTCHA verification failed for login attempt. Email: {Email}, Errors: {Errors}",
                request.Email, string.Join(", ", captchaResult.ErrorCodes ?? Array.Empty<string>()));

            return BadRequest(new
            {
                success = false,
                message = "CAPTCHA verification failed",
                error = "Bot detected or invalid CAPTCHA",
                details = captchaResult.ErrorCodes
            });
        }

        _logger.LogInformation("✅ CAPTCHA verified. Score: {Score}", captchaResult.Score);

        // STEP 2: Proceed with normal login after CAPTCHA verification
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());

        if (user == null || user.PasswordHash == null)
        {
            _logger.LogWarning("Login attempt with non-existent user: {Email}", request.Email);
            // Don't reveal whether user exists - always same message
            return Unauthorized(new { success = false, message = "Invalid credentials" });
        }

        var passwordResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

        if (passwordResult == PasswordVerificationResult.Success)
        {
            _logger.LogInformation("✅ SECURE: Login successful with CAPTCHA verification for {Email}", user.Email);
            return Ok(new
            {
                success = true,
                message = "Login successful",
                security = "✅ Protected by CAPTCHA - bot attacks prevented",
                userId = user.Id,
                email = user.Email,
                captchaScore = captchaResult.Score
            });
        }

        _logger.LogWarning("Invalid password attempt for {Email}", request.Email);
        return Unauthorized(new { success = false, message = "Invalid credentials" });
    }

    /// <summary>
    /// ✅ SECURE: Registration with CAPTCHA protection
    /// Prevents automated bot registrations
    /// </summary>
    [HttpPost("register-with-captcha")]
    public async Task<IActionResult> RegisterWithCaptcha([FromBody] RegisterWithCaptchaRequest request)
    {
        _logger.LogInformation("✅ SECURE ENDPOINT: register-with-captcha");

        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                success = false,
                message = "Validation failed",
                errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)
            });
        }

        // STEP 1: Verify CAPTCHA first (before any database operations)
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var captchaResult = await _captchaService.VerifyAsync(request.CaptchaToken, remoteIp);

        if (!captchaResult.Success)
        {
            _logger.LogWarning("CAPTCHA verification failed for registration. Email: {Email}", request.Email);

            return BadRequest(new
            {
                success = false,
                message = "CAPTCHA verification failed",
                error = "Bot detected or invalid CAPTCHA",
                details = captchaResult.ErrorCodes
            });
        }

        _logger.LogInformation("✅ CAPTCHA verified for registration. Score: {Score}", captchaResult.Score);

        // STEP 2: Check if email already exists
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());

        if (existingUser != null)
        {
            return BadRequest(new
            {
                success = false,
                message = "Email already registered"
            });
        }

        // STEP 3: Create new user with hashed password
        var user = new User
        {
            Email = request.Email.ToLower().Trim(),
            CreatedAt = DateTime.UtcNow
        };

        user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("✅ User registered successfully with CAPTCHA protection: {Email}", user.Email);

        return Ok(new
        {
            success = true,
            message = "User registered successfully",
            security = "✅ Protected by CAPTCHA - bot registrations prevented",
            userId = user.Id,
            email = user.Email,
            captchaScore = captchaResult.Score
        });
    }

    /// <summary>
    /// Demo endpoint to test CAPTCHA verification without side effects
    /// </summary>
    [HttpPost("test-captcha")]
    public async Task<IActionResult> TestCaptcha([FromBody] Dictionary<string, string> request)
    {
        if (!request.TryGetValue("captchaToken", out var token))
        {
            return BadRequest(new { success = false, message = "Missing captchaToken" });
        }

        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _captchaService.VerifyAsync(token, remoteIp);

        return Ok(new
        {
            success = result.Success,
            message = result.Success ? "CAPTCHA verified successfully" : "CAPTCHA verification failed",
            details = new
            {
                score = result.Score,
                action = result.Action,
                challengeTs = result.ChallengeTs,
                hostname = result.Hostname,
                errorCodes = result.ErrorCodes,
                remoteIp
            }
        });
    }

    // ==================== STEP 6: JWT AUTHENTICATION ====================

    /// <summary>
    /// STEP 6A: Login WITHOUT JWT (old session-based approach)
    /// Demonstrates: Traditional approach - server stores session state
    /// Problem: Not scalable, doesn't work with multiple servers/microservices
    /// </summary>
    [HttpPost("login-no-jwt")]
    public async Task<IActionResult> LoginNoJwt([FromBody] JwtLoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                success = false,
                message = "Validation failed",
                errors = ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
            });
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

        if (user == null || string.IsNullOrEmpty(user.PasswordHash))
        {
            return Unauthorized(new
            {
                success = false,
                message = "Invalid credentials",
                warning = "⚠️ This endpoint uses traditional session-based auth - not suitable for modern APIs/microservices"
            });
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

        if (result == PasswordVerificationResult.Failed)
        {
            return Unauthorized(new
            {
                success = false,
                message = "Invalid credentials",
                warning = "⚠️ Session-based auth doesn't scale horizontally (sticky sessions required)"
            });
        }

        // Traditional approach: Store session on server (NOT SCALABLE)
        _logger.LogInformation("User {Email} logged in (session-based, no JWT)", user.Email);

        return Ok(new
        {
            success = true,
            message = "Login successful (session-based)",
            warning = "⚠️ No JWT token - relies on server-side session storage",
            limitations = new[]
            {
                "Server must store session state",
                "Doesn't work across multiple servers without sticky sessions",
                "Difficult to use with mobile apps or microservices",
                "Session data lost if server restarts"
            }
        });
    }

    /// <summary>
    /// STEP 6B: Login WITH JWT (modern stateless approach)
    /// Returns JWT token containing user claims
    /// Token is signed with server secret - prevents tampering
    /// </summary>
    [HttpPost("login-with-jwt")]
    public async Task<IActionResult> LoginWithJwt([FromBody] JwtLoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new
            {
                success = false,
                message = "Validation failed",
                errors = ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
            });
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

        if (user == null || string.IsNullOrEmpty(user.PasswordHash))
        {
            return Unauthorized(new { success = false, message = "Invalid credentials" });
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

        if (result == PasswordVerificationResult.Failed)
        {
            return Unauthorized(new { success = false, message = "Invalid credentials" });
        }

        // Generate JWT token
        var token = _jwtTokenService.GenerateToken(user);
        var expiresAt = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:ExpirationMinutes"] ?? "60"));

        _logger.LogInformation("User {Email} logged in with JWT token", user.Email);

        return Ok(new LoginResponse
        {
            Success = true,
            Message = "Login successful - JWT token generated",
            Token = token,
            ExpiresAt = expiresAt,
            User = new UserInfo
            {
                Id = user.Id,
                Email = user.Email
            }
        });
    }

    /// <summary>
    /// STEP 6C: Protected endpoint - requires valid JWT token
    /// Demonstrates [Authorize] attribute for API protection
    /// </summary>
    [Authorize]
    [HttpGet("profile")]
    public async Task<IActionResult> GetProfile()
    {
        // Extract user ID from JWT claims
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            return Unauthorized(new { success = false, message = "Invalid token claims" });
        }

        var user = await _context.Users.FindAsync(userId);

        if (user == null)
        {
            return NotFound(new { success = false, message = "User not found" });
        }

        _logger.LogInformation("User {Email} accessed protected profile endpoint", user.Email);

        return Ok(new
        {
            success = true,
            message = "✅ Protected endpoint accessed successfully with JWT",
            user = new
            {
                id = user.Id,
                email = user.Email,
                createdAt = user.CreatedAt
            },
            tokenInfo = new
            {
                claims = User.Claims.Select(c => new { c.Type, c.Value }).ToArray(),
                authenticated = User.Identity?.IsAuthenticated ?? false,
                authType = User.Identity?.AuthenticationType
            }
        });
    }

    /// <summary>
    /// STEP 6D: Unprotected endpoint - no JWT required (for comparison)
    /// Anyone can access this without authentication
    /// </summary>
    [HttpGet("public-info")]
    public IActionResult GetPublicInfo()
    {
        _logger.LogInformation("Public endpoint accessed (no authentication required)");

        return Ok(new
        {
            success = true,
            message = "✅ Public endpoint - no authentication required",
            info = new
            {
                serverTime = DateTime.UtcNow,
                version = "1.0.0",
                endpoints = new
                {
                    publicAccess = "/api/auth/public-info",
                    protectedAccess = "/api/auth/profile (requires JWT token)"
                }
            }
        });
    }

    /// <summary>
    /// STEP 6E: Admin endpoint - requires valid JWT + admin claim (future enhancement)
    /// Demonstrates role-based authorization
    /// </summary>
    [Authorize(Roles = "Admin")]
    [HttpGet("admin/users")]
    public async Task<IActionResult> GetAllUsersAdmin()
    {
        _logger.LogInformation("Admin endpoint accessed");

        var users = await _context.Users
            .Select(u => new
            {
                u.Id,
                u.Email,
                u.CreatedAt,
                hasPassword = !string.IsNullOrEmpty(u.PasswordHash)
            })
            .ToListAsync();

        return Ok(new
        {
            success = true,
            message = "✅ Admin endpoint accessed successfully",
            count = users.Count,
            users
        });
    }

    #region STEP 7: Multi-Factor Authentication (MFA) - Google Authenticator (TOTP)

    /// <summary>
    /// STEP 7: Enable MFA for a user
    /// Generates a TOTP secret and QR code for Google Authenticator
    /// </summary>
    [HttpPost("enable-mfa")]
    public async Task<IActionResult> EnableMfa([FromBody] EnableMfaRequest request)
    {
        try
        {
            var user = await _context.Users.FindAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new { success = false, message = "User not found" });
            }

            if (user.MfaEnabled)
            {
                return BadRequest(new { success = false, message = "MFA is already enabled for this user" });
            }

            // Generate new TOTP secret
            var secret = _mfaService.GenerateSecret();
            
            // Generate QR code for Google Authenticator
            var qrCodeDataUrl = _mfaService.GenerateQrCodeDataUrl(
                user.Email, 
                secret, 
                "PasswordSecurityDemo"
            );

            // Store the secret (but don't activate MFA yet - wait for confirmation)
            user.MfaSecret = secret;
            user.MfaEnabled = false; // Will be set to true after confirmation
            await _context.SaveChangesAsync();

            return Ok(new EnableMfaResponse
            {
                Success = true,
                Message = "MFA setup initiated. Scan QR code with Google Authenticator and confirm with a code.",
                Secret = secret, // Include for backup
                QrCodeDataUrl = qrCodeDataUrl,
                Instructions = new List<string>
                {
                    "1. Install Google Authenticator on your phone",
                    "2. Scan the QR code with the app",
                    "3. Enter the 6-digit code to confirm setup",
                    "4. Save the secret key in a safe place as backup"
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error enabling MFA for user {UserId}", request.UserId);
            return StatusCode(500, new { success = false, message = "An error occurred while enabling MFA" });
        }
    }

    /// <summary>
    /// STEP 7: Confirm MFA setup by verifying the first code
    /// </summary>
    [HttpPost("confirm-mfa")]
    public async Task<IActionResult> ConfirmMfa([FromBody] ConfirmMfaRequest request)
    {
        try
        {
            var user = await _context.Users.FindAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new { success = false, message = "User not found" });
            }

            if (string.IsNullOrEmpty(user.MfaSecret))
            {
                return BadRequest(new { success = false, message = "MFA setup not initiated. Call enable-mfa first." });
            }

            if (user.MfaEnabled)
            {
                return BadRequest(new { success = false, message = "MFA is already enabled and confirmed" });
            }

            // Verify the code
            var isValid = _mfaService.VerifyTotp(user.MfaSecret, request.Code);
            if (!isValid)
            {
                return BadRequest(new { success = false, message = "Invalid verification code. Please try again." });
            }

            // Activate MFA
            user.MfaEnabled = true;
            await _context.SaveChangesAsync();

            _logger.LogInformation("MFA enabled for user {Email}", user.Email);

            return Ok(new
            {
                success = true,
                message = "✅ MFA successfully enabled! Your account is now protected with two-factor authentication.",
                mfaEnabled = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming MFA for user {UserId}", request.UserId);
            return StatusCode(500, new { success = false, message = "An error occurred while confirming MFA" });
        }
    }

    /// <summary>
    /// STEP 7: Disable MFA for a user (requires password verification)
    /// </summary>
    [HttpPost("disable-mfa")]
    public async Task<IActionResult> DisableMfa([FromBody] DisableMfaRequest request)
    {
        try
        {
            var user = await _context.Users.FindAsync(request.UserId);
            if (user == null)
            {
                return NotFound(new { success = false, message = "User not found" });
            }

            if (!user.MfaEnabled)
            {
                return BadRequest(new { success = false, message = "MFA is not enabled for this user" });
            }

            // Verify password before disabling MFA (security check)
            if (string.IsNullOrEmpty(user.PasswordHash))
            {
                return BadRequest(new { success = false, message = "User has no password set" });
            }

            var passwordValid = _passwordHasher.VerifyHashedPassword(
                user, 
                user.PasswordHash, 
                request.Password
            );

            if (passwordValid != PasswordVerificationResult.Success)
            {
                return BadRequest(new { success = false, message = "Invalid password" });
            }

            // Disable MFA
            user.MfaEnabled = false;
            user.MfaSecret = null; // Clear the secret
            await _context.SaveChangesAsync();

            _logger.LogWarning("MFA disabled for user {Email}", user.Email);

            return Ok(new
            {
                success = true,
                message = "⚠️ MFA has been disabled. Your account is now less secure.",
                mfaEnabled = false
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disabling MFA for user {UserId}", request.UserId);
            return StatusCode(500, new { success = false, message = "An error occurred while disabling MFA" });
        }
    }

    /// <summary>
    /// STEP 7: Login WITHOUT MFA verification (VULNERABLE)
    /// Shows the problem: Even if the user has MFA enabled, this endpoint ignores it
    /// This is what happens when MFA is optional or not properly enforced
    /// </summary>
    [HttpPost("login-without-mfa")]
    public async Task<IActionResult> LoginWithoutMfa([FromBody] LoginRequest request)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null || string.IsNullOrEmpty(user.PasswordHash))
            {
                return BadRequest(new { success = false, message = "Invalid credentials" });
            }

            var passwordValid = _passwordHasher.VerifyHashedPassword(
                user, 
                user.PasswordHash, 
                request.Password
            );

            if (passwordValid != PasswordVerificationResult.Success)
            {
                return BadRequest(new { success = false, message = "Invalid credentials" });
            }

            // ⚠️ VULNERABILITY: We're not checking if MFA is enabled!
            // This allows attackers with stolen passwords to bypass MFA entirely

            _logger.LogWarning(
                "🚨 VULNERABLE LOGIN: User {Email} logged in without MFA check. MfaEnabled={MfaEnabled}",
                user.Email,
                user.MfaEnabled
            );

            var token = _jwtTokenService.GenerateToken(user);

            return Ok(new
            {
                success = true,
                message = user.MfaEnabled 
                    ? "⚠️ WARNING: You logged in without MFA verification even though MFA is enabled!" 
                    : "✅ Login successful (no MFA configured)",
                token,
                userId = user.Id,
                email = user.Email,
                mfaEnabled = user.MfaEnabled,
                vulnerability = "This endpoint doesn't enforce MFA, making it vulnerable to credential stuffing attacks"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in vulnerable login");
            return StatusCode(500, new { success = false, message = "An error occurred during login" });
        }
    }

    /// <summary>
    /// STEP 7: Login WITH MFA verification (SECURE) - Step 1: Password verification
    /// Two-step flow: First verify password, then require MFA code
    /// This blocks credential stuffing attacks because stolen passwords alone aren't enough
    /// </summary>
    [HttpPost("login-with-mfa")]
    public async Task<IActionResult> LoginWithMfa([FromBody] LoginWithMfaRequest request)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null || string.IsNullOrEmpty(user.PasswordHash))
            {
                return Unauthorized(new { success = false, message = "Invalid credentials" });
            }

            // Step 1: Verify password
            var passwordValid = _passwordHasher.VerifyHashedPassword(
                user, 
                user.PasswordHash, 
                request.Password
            );

            if (passwordValid != PasswordVerificationResult.Success)
            {
                return Unauthorized(new { success = false, message = "Invalid credentials" });
            }

            // Step 2: Check if MFA is enabled for this user
            if (user.MfaEnabled)
            {
                // For two-step flow, return MFA token for next step
                var mfaToken = Guid.NewGuid().ToString();
                
                // Cache the user ID with mfaToken (in production, use Redis/distributed cache)
                // For demo, we'll use a simple in-memory approach via the token itself
                var tokenData = Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes($"{user.Id}:{DateTime.UtcNow:O}")
                );

                _logger.LogInformation("Password verified for user {Email}, MFA required", user.Email);

                return Ok(new
                {
                    success = false,
                    requiresMfa = true,
                    message = "Password verified. Please enter your MFA code.",
                    mfaToken = tokenData,
                    userId = user.Id
                });
            }

            // No MFA - generate JWT token immediately
            var token = _jwtTokenService.GenerateToken(user);

            _logger.LogInformation("✅ Login successful for user {Email} (no MFA)", user.Email);

            return Ok(new
            {
                success = true,
                message = "✅ Login successful (no MFA configured)",
                token,
                userId = user.Id,
                email = user.Email,
                mfaEnabled = false,
                security = "Consider enabling MFA for better security"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in MFA login step 1");
            return StatusCode(500, new { success = false, message = "An error occurred during login" });
        }
    }

    /// <summary>
    /// STEP 7: Verify MFA code and complete login (SECURE) - Step 2: MFA verification
    /// Validates TOTP code and returns JWT token
    /// </summary>
    [HttpPost("verify-mfa-login")]
    public async Task<IActionResult> VerifyMfaLogin([FromBody] VerifyMfaLoginRequest request)
    {
        try
        {
            // Decode mfaToken to get user ID
            var tokenData = System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(request.MfaToken)
            );
            
            var parts = tokenData.Split(':');
            if (parts.Length != 2 || !int.TryParse(parts[0], out var userId))
            {
                return BadRequest(new { success = false, message = "Invalid MFA token" });
            }

            // Check token age (valid for 5 minutes)
            if (DateTime.TryParse(parts[1], out var tokenTime))
            {
                if (DateTime.UtcNow - tokenTime > TimeSpan.FromMinutes(5))
                {
                    return BadRequest(new { 
                        success = false, 
                        message = "MFA token expired. Please login again." 
                    });
                }
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null || !user.MfaEnabled || string.IsNullOrEmpty(user.MfaSecret))
            {
                return BadRequest(new { success = false, message = "Invalid user or MFA not enabled" });
            }

            // Verify TOTP code
            var isMfaValid = _mfaService.VerifyTotp(user.MfaSecret, request.Code);
            if (!isMfaValid)
            {
                _logger.LogWarning(
                    "Failed MFA verification for user {Email}. Code: {Code}",
                    user.Email,
                    request.Code
                );
                
                return BadRequest(new { 
                    success = false, 
                    message = "Invalid MFA code. Please check your authenticator app and try again." 
                });
            }

            // Generate JWT token
            var token = _jwtTokenService.GenerateToken(user);

            _logger.LogInformation("✅ Successful MFA login for user {Email}", user.Email);

            return Ok(new
            {
                success = true,
                message = "✅ Login successful with MFA verification",
                token,
                user = new
                {
                    id = user.Id,
                    email = user.Email
                },
                mfaEnabled = true,
                security = "Your account is protected by two-factor authentication ✓"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in MFA verification");
            return StatusCode(500, new { success = false, message = "An error occurred during MFA verification" });
        }
    }

    #endregion

    #region STEP 8: Security Logging Demonstration

    /// <summary>
    /// BAD EXAMPLE: Login without any security logging
    /// PROBLEM: No audit trail, can't detect attacks or investigate breaches
    /// </summary>
    [HttpPost("login-no-logging")]
    public async Task<IActionResult> LoginNoLogging([FromBody] LoginRequest request)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());
        
        if (user == null)
        {
            // NO LOGGING - Security team has no visibility
            return Unauthorized(new 
            { 
                success = false, 
                message = "Invalid credentials",
                vulnerability = "⚠️ No logging - Failed login attempts are invisible to security team"
            });
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            return Unauthorized(new { success = false, message = "Account configuration error" });
        }

        var passwordValid = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        
        if (passwordValid != PasswordVerificationResult.Success)
        {
            // NO LOGGING - Brute force attacks go undetected
            return Unauthorized(new 
            { 
                success = false, 
                message = "Invalid credentials",
                vulnerability = "⚠️ No logging - Brute force attacks cannot be detected"
            });
        }

        var token = _jwtTokenService.GenerateToken(user);

        // NO LOGGING - Can't prove who accessed what and when
        return Ok(new
        {
            success = true,
            message = "Login successful",
            token,
            vulnerability = "⚠️ No audit trail - Can't investigate breaches or prove compliance"
        });
    }

    /// <summary>
    /// GOOD EXAMPLE: Login WITH comprehensive security logging
    /// BENEFIT: Full audit trail, threat detection, forensic capability
    /// </summary>
    [HttpPost("login-with-logging")]
    public async Task<IActionResult> LoginWithLogging([FromBody] LoginRequest request)
    {
        var clientIp = GetClientIp();
        var userAgent = GetUserAgent();

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());
        
        if (user == null)
        {
            // LOG: Failed login attempt (unknown user)
            await _securityLog.LogLoginFailure(
                request.Email, 
                clientIp, 
                userAgent, 
                "User not found");

            return Unauthorized(new 
            { 
                success = false, 
                message = "Invalid credentials",
                security = "✅ Failed attempt logged for security monitoring"
            });
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            return Unauthorized(new { success = false, message = "Account configuration error" });
        }

        var passwordValid = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        
        if (passwordValid != PasswordVerificationResult.Success)
        {
            // LOG: Failed login attempt (wrong password)
            await _securityLog.LogSecurityEvent(new SecurityLogEntry
            {
                EventType = SecurityEventType.InvalidPassword,
                Email = user.Email,
                UserId = user.Id.ToString(),
                IpAddress = clientIp,
                UserAgent = userAgent,
                Message = "Invalid password attempt"
            });

            return Unauthorized(new 
            { 
                success = false, 
                message = "Invalid credentials",
                security = "✅ Invalid password attempt logged - Security team can detect brute force"
            });
        }

        // LOG: Successful login
        await _securityLog.LogLoginSuccess(
            user.Email, 
            user.Id.ToString(), 
            clientIp, 
            userAgent, 
            user.MfaEnabled);

        var token = _jwtTokenService.GenerateToken(user);

        return Ok(new
        {
            success = true,
            message = "Login successful",
            token,
            security = "✅ Login event logged - Full audit trail available for compliance and forensics"
        });
    }

    /// <summary>
    /// STEP 8: Simulate SQL injection attempt (triggers logging)
    /// </summary>
    [HttpPost("test-sql-injection-logging")]
    public async Task<IActionResult> TestSqlInjectionLogging([FromBody] TestSecurityLogRequest request)
    {
        var clientIp = GetClientIp();
        var userAgent = GetUserAgent();

        // Detect SQL injection patterns
        var sqlPatterns = new[] { "' OR '1'='1", "'; DROP TABLE", "1' OR '1'='1", "admin'--" };
        
        if (sqlPatterns.Any(pattern => request.Input.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
        {
            // LOG: SQL injection attempt detected
            await _securityLog.LogSqlInjectionAttempt(request.Input, clientIp, userAgent);

            return BadRequest(new
            {
                success = false,
                message = "Malicious input detected",
                security = "🚨 SQL injection attempt logged to security log",
                logged = new
                {
                    eventType = "SqlInjectionAttempt",
                    severity = "CRITICAL",
                    ipAddress = clientIp,
                    suspiciousInput = request.Input
                }
            });
        }

        return Ok(new { success = true, message = "Input is clean" });
    }

    /// <summary>
    /// STEP 8: Simulate XSS attempt (triggers logging)
    /// </summary>
    [HttpPost("test-xss-logging")]
    public async Task<IActionResult> TestXssLogging([FromBody] TestSecurityLogRequest request)
    {
        var clientIp = GetClientIp();
        var userAgent = GetUserAgent();

        // Detect XSS patterns
        var xssPatterns = new[] { "<script>", "javascript:", "onerror=", "onclick=" };
        
        if (xssPatterns.Any(pattern => request.Input.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
        {
            // LOG: XSS attempt detected
            await _securityLog.LogXssAttempt(request.Input, clientIp, userAgent);

            return BadRequest(new
            {
                success = false,
                message = "Malicious content detected",
                security = "🚨 XSS attempt logged to security log",
                logged = new
                {
                    eventType = "XssAttemptDetected",
                    severity = "CRITICAL",
                    ipAddress = clientIp,
                    suspiciousInput = request.Input
                }
            });
        }

        return Ok(new { success = true, message = "Content is clean" });
    }

    /// <summary>
    /// STEP 8: Demonstrate MFA failure logging
    /// </summary>
    [HttpPost("test-mfa-failure-logging")]
    public async Task<IActionResult> TestMfaFailureLogging()
    {
        var clientIp = GetClientIp();
        var userAgent = GetUserAgent();

        // Simulate MFA failure
        await _securityLog.LogMfaEvent(
            SecurityEventType.MfaFailure,
            "test@example.com",
            "test-user-id",
            clientIp,
            userAgent,
            "Invalid MFA code provided");

        return Ok(new
        {
            success = false,
            message = "MFA verification failed",
            security = "✅ MFA failure logged - Multiple failures could indicate account takeover attempt",
            logged = new
            {
                eventType = "MfaFailure",
                severity = "WARNING",
                ipAddress = clientIp
            }
        });
    }

    #endregion
}

