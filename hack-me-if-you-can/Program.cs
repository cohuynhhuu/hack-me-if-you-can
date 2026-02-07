using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PasswordSecurityDemo.Data;
using PasswordSecurityDemo.Models;
using PasswordSecurityDemo.Services;
using HackMeIfYouCan.Services; // STEP 8
using System.Text;
using Serilog;
using Serilog.Formatting.Compact;

// STEP 8: Configure Serilog for structured logging
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("System", Serilog.Events.LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File(
        new CompactJsonFormatter(),
        path: "logs/security-logs-.json",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);

// STEP 8: Use Serilog for logging
builder.Host.UseSerilog();

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddRazorPages(); // STEP 8: Add Razor Pages for demo UI
builder.Services.AddEndpointsApiExplorer();

// Configure SQL Server database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register PasswordHasher service
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

// Register CAPTCHA service with HttpClient
builder.Services.AddHttpClient<ICaptchaService, CaptchaService>();

// Register JWT Token service
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

// Register MFA service
builder.Services.AddScoped<IMfaService, MfaService>();

// STEP 8: Register Security Logging service
builder.Services.AddScoped<SecurityLogService>();

// Configure JWT Authentication
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var jwtSecretKey = builder.Configuration["Jwt:SecretKey"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey!)),
        ClockSkew = TimeSpan.Zero // No tolerance for expired tokens
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Apply migrations automatically on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
}

// Configure the HTTP request pipeline
app.UseHttpsRedirection();

// STEP 8: Enable Serilog request logging (logs all HTTP requests)
app.UseSerilogRequestLogging();

// Enable static files (for wwwroot)
app.UseStaticFiles();

// Authentication must come before Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages(); // STEP 8: Map Razor Pages for demo UI

app.Run();

// STEP 8: Ensure logs are flushed before app closes
Log.CloseAndFlush();
