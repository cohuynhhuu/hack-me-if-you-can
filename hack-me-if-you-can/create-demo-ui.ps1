# Security Demo UI Generator Script

Write-Host "Creating Security Demo UI..." -ForegroundColor Cyan

# Create folder structure
New-Item -Path "Pages/Shared" -ItemType Directory -Force | Out-Null
New-Item -Path "wwwroot/css" -ItemType Directory -Force | Out-Null
New-Item -Path "wwwroot/js" -ItemType Directory -Force | Out-Null

Write-Host "✓ Folder structure created" -ForegroundColor Green
Write-Host "✓ Ready for file creation" -ForegroundColor Green
Write-Host ""
Write-Host "Next: Files will be created individually..." -ForegroundColor Yellow
