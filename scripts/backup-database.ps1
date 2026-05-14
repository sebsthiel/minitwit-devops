$ErrorActionPreference = "Stop"

$SSH_KEY  = "$env:USERPROFILE\.ssh\minitwit_do"
$SSH_OPTS = @("-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-i", $SSH_KEY)

# Your current live DB droplet IP
$DB_IP = "104.248.247.141"

Write-Host ""
Write-Host "Backing up MiniTwit database..."
Write-Host ""

# Create backup folder if it does not exist
if (-not (Test-Path ".\backup")) {
    New-Item -ItemType Directory -Path ".\backup" | Out-Null
}

# Dump the database from the live droplet to your laptop
Write-Host "Dumping database from $DB_IP ..."
ssh @SSH_OPTS "root@$DB_IP" "sudo -u postgres pg_dump -Fc minitwit" | `
    Set-Content -AsByteStream ".\backup\minitwit.pgdump"

# Check the file actually has something in it
$size = (Get-Item ".\backup\minitwit.pgdump").Length
Write-Host "Backup size: $size bytes"

if ($size -lt 100) {
    Write-Host ""
    Write-Host "WARNING: Backup file looks too small. Something may have gone wrong."
    Write-Host "Do NOT delete your droplets until you have a good backup."
} else {
    Write-Host ""
    Write-Host "Backup saved to: .\backup\minitwit.pgdump"
    Write-Host "Backup looks good."
    Write-Host ""
    Write-Host "You can now safely delete your old droplets and run:"
    Write-Host ".\scripts\create-infrastructure.ps1 -Apply"
}