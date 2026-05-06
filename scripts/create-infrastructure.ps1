param(
    [switch]$Apply
)

$ErrorActionPreference = "Stop"

$PROJECT = "minitwit"

# Existing SSH key
$SSH_KEY_PATH = "$env:USERPROFILE\.ssh\minitwit_do.pub"

# Droplet names
$DB_NAME = "minitwit-db"
$MANAGER_NAME = "swarm-manager"
$WORKER_NAME = "swarm-worker"

# Region / size
$REGION = "fra1"
$SIZE = "s-1vcpu-1gb"
$IMAGE = "ubuntu-22-04-x64"

Write-Host ""
Write-Host "MiniTwit Infrastructure Provisioning"
Write-Host ""

Write-Host "This script will:"
Write-Host "- Create database droplet"
Write-Host "- Create swarm manager"
Write-Host "- Create swarm worker"
Write-Host "- Prepare infrastructure for deployment"
Write-Host ""

if (-not $Apply) {
    Write-Host "DRY RUN MODE"
    Write-Host ""
    Write-Host "Nothing will actually be created."
    Write-Host ""
    Write-Host "To really create infrastructure run:"
    Write-Host ""
    Write-Host ".\scripts\create-infrastructure.ps1 -Apply"
    exit
}

Write-Host ""
Write-Host "Creating database droplet..."

doctl compute droplet create $DB_NAME `
    --size $SIZE `
    --image $IMAGE `
    --region $REGION `
    --ssh-keys $SSH_KEY_PATH `
    --wait

Write-Host ""
Write-Host "Creating swarm manager..."

doctl compute droplet create $MANAGER_NAME `
    --size $SIZE `
    --image $IMAGE `
    --region $REGION `
    --ssh-keys $SSH_KEY_PATH `
    --wait

Write-Host ""
Write-Host "Creating swarm worker..."

doctl compute droplet create $WORKER_NAME `
    --size $SIZE `
    --image $IMAGE `
    --region $REGION `
    --ssh-keys $SSH_KEY_PATH `
    --wait

Write-Host ""
Write-Host "Infrastructure creation complete."
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Install PostgreSQL on DB droplet"
Write-Host "2. Restore database backup"
Write-Host "3. Install Docker on manager + worker"
Write-Host "4. Initialize Docker Swarm"
Write-Host "5. Run deploy-existing.ps1"