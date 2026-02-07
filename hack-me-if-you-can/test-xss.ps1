# XSS (Cross-Site Scripting) Prevention Test Script
# This script demonstrates XSS attacks on vulnerable endpoints and protection on secure endpoints

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   XSS Prevention Demonstration - STEP 4       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:5000/api/auth"

# Add required assembly for URL encoding
Add-Type -AssemblyName System.Web

Write-Host "This demonstration will:" -ForegroundColor Yellow
Write-Host "1. Open vulnerable pages that execute malicious scripts" -ForegroundColor Yellow
Write-Host "2. Open secure pages that display scripts as text" -ForegroundColor Yellow
Write-Host "3. Show side-by-side comparison in interactive demo" -ForegroundColor Yellow
Write-Host ""
Write-Host "⚠️  Warning: You will see alert popups from vulnerable pages!" -ForegroundColor Red
Write-Host ""

$continue = Read-Host "Press ENTER to continue or CTRL+C to cancel"

# Test payloads with explanations
$tests = @(
    @{
        Name = "Basic Script Alert"
        Payload = "<script>alert('XSS Attack!')</script>"
        Description = "Classic XSS payload - directly injects JavaScript alert"
    },
    @{
        Name = "Image Tag with onerror"
        Payload = "<img src=x onerror=alert('XSS via Image!')>"
        Description = "Uses invalid image to trigger error handler"
    },
    @{
        Name = "SVG onload Event"
        Payload = "<svg onload=alert('XSS via SVG!')>"
        Description = "SVG element with event handler"
    }
)

foreach ($test in $tests) {
    Write-Host "`n═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Test: $($test.Name)" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📝 Payload: " -NoNewline
    Write-Host $test.Payload -ForegroundColor Yellow
    Write-Host "💡 Description: $($test.Description)" -ForegroundColor Gray
    Write-Host ""
    
    $encoded = [System.Web.HttpUtility]::UrlEncode($test.Payload)
    
    # Test vulnerable endpoint
    Write-Host "🚨 Testing VULNERABLE endpoint..." -ForegroundColor Red
    Write-Host "   Opening: $baseUrl/profile-vulnerable?name=$($test.Payload)" -ForegroundColor DarkGray
    Write-Host "   Expected: " -NoNewline
    Write-Host "Alert popup will appear (XSS attack successful!)" -ForegroundColor Red
    
    try {
        Start-Process "$baseUrl/profile-vulnerable?name=$encoded"
        Write-Host "   Result: " -NoNewline
        Write-Host "⚠️  Page opened - script will execute!" -ForegroundColor Red
    }
    catch {
        Write-Host "   Error: Failed to open browser - $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Start-Sleep -Seconds 3
    
    # Test secure endpoint
    Write-Host ""
    Write-Host "✅ Testing SECURE endpoint..." -ForegroundColor Green
    Write-Host "   Opening: $baseUrl/profile-secure?name=$($test.Payload)" -ForegroundColor DarkGray
    Write-Host "   Expected: " -NoNewline
    Write-Host "Script displayed as text (XSS blocked!)" -ForegroundColor Green
    
    try {
        Start-Process "$baseUrl/profile-secure?name=$encoded"
        Write-Host "   Result: " -NoNewline
        Write-Host "✅ Page opened - script rendered as harmless text!" -ForegroundColor Green
    }
    catch {
        Write-Host "   Error: Failed to open browser - $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "⏸️  Pausing for 3 seconds..." -ForegroundColor Gray
    Start-Sleep -Seconds 3
}

# Open interactive demo
Write-Host "`n═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Opening Interactive Demo Page" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎯 This page shows:" -ForegroundColor Yellow
Write-Host "   • Side-by-side vulnerable vs secure comparison" -ForegroundColor White
Write-Host "   • Live encoding demonstration" -ForegroundColor White
Write-Host "   • Multiple attack payload examples" -ForegroundColor White
Write-Host "   • Educational explanations" -ForegroundColor White
Write-Host ""

try {
    Start-Process "$baseUrl/xss-demo"
    Write-Host "✅ Interactive demo opened successfully!" -ForegroundColor Green
}
catch {
    Write-Host "❌ Error: Failed to open demo - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Test Complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "📚 Key Learnings:" -ForegroundColor Yellow
Write-Host "   1. Vulnerable pages execute malicious scripts" -ForegroundColor White
Write-Host "   2. Secure pages HTML-encode input to display as text" -ForegroundColor White
Write-Host "   3. HttpUtility.HtmlEncode() prevents XSS attacks" -ForegroundColor White
Write-Host "   4. Always encode user input before rendering" -ForegroundColor White
Write-Host ""
Write-Host "🔒 Security Reminder:" -ForegroundColor Cyan
Write-Host "   • Never trust user input" -ForegroundColor White
Write-Host "   • Always encode output based on context" -ForegroundColor White
Write-Host "   • Use framework features that auto-encode (Razor Pages)" -ForegroundColor White
Write-Host "   • Implement Content Security Policy (CSP) headers" -ForegroundColor White
Write-Host ""
Write-Host "📖 For detailed documentation, see: STEP4-XSS-PREVENTION.md" -ForegroundColor Gray
Write-Host ""

# Test API endpoint (JSON - safe by default)
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Bonus: Testing JSON API Endpoint" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing POST /api/auth/comment with XSS payload..." -ForegroundColor Yellow

$commentPayload = @{
    content = "<script>alert('XSS in JSON')</script>"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/comment" -Method Post `
        -ContentType "application/json" -Body $commentPayload
    
    Write-Host "✅ JSON API Response (automatically safe):" -ForegroundColor Green
    Write-Host ($response | ConvertTo-Json -Depth 3) -ForegroundColor White
    Write-Host ""
    Write-Host "💡 Note: JSON serialization automatically escapes special characters!" -ForegroundColor Cyan
}
catch {
    Write-Host "❌ API Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
