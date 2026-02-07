Write-Host "Creating Security Demo UI Files..." -ForegroundColor Cyan

# Ensure directories exist
"Pages", "Pages/Shared", "wwwroot/css", "wwwroot/js" | ForEach-Object {
    New-Item -Path $_ -ItemType Directory -Force | Out-Null
}

Write-Host "Directories created successfully" -ForegroundColor Green

# Create _ViewStart.cshtml
Set-Content -Path "Pages/_ViewStart.cshtml" -Value '@{
    Layout = "_Layout";
}'

Write-Host "✓ _ViewStart.cshtml created" -ForegroundColor Green

# Note: Additional files will be created in subsequent steps
Write-Host ""
Write-Host "Base setup complete!" -ForegroundColor Cyan
Write-Host "Ready to add individual page files..." -ForegroundColor Yellow
