$ErrorActionPreference = "Stop"

$SSH_KEY  = "$env:USERPROFILE\.ssh\minitwit_do"
$SSH_OPTS = @("-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-i", $SSH_KEY)

$DB_PASS        = "minitwitpw123"
$SIMULATOR_AUTH = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

# ── Load IPs saved by create-infrastructure.ps1 ──
$IPS_FILE = "$PSScriptRoot\infrastructure-ips.ps1"

if (Test-Path $IPS_FILE) {
    Write-Host "Loading IPs from infrastructure-ips.ps1..."
    . $IPS_FILE
    Write-Host "  DB      : $DB_IP"
    Write-Host "  Manager : $MANAGER_IP"
} else {
    Write-Host "No infrastructure-ips.ps1 found — using hardcoded IPs."
    $DB_IP      = "104.248.247.141"
    $MANAGER_IP = "157.230.121.187"
}

# ── Where the compose files are ──
$PROJECT_ROOT = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "Deploying MiniTwit to $MANAGER_IP ..."

Write-Host ""
Write-Host "Creating folder on manager..."
ssh @SSH_OPTS "root@$MANAGER_IP" "mkdir -p /opt/minitwit"

Write-Host "Copying files to manager..."
scp @SSH_OPTS "$PROJECT_ROOT\docker-compose.yml"            "root@${MANAGER_IP}:/opt/minitwit/docker-compose.yml"
scp @SSH_OPTS "$PROJECT_ROOT\docker-compose.monitoring.yml" "root@${MANAGER_IP}:/opt/minitwit/docker-compose.monitoring.yml"
scp @SSH_OPTS "$PROJECT_ROOT\nginx.conf"                    "root@${MANAGER_IP}:/opt/minitwit/nginx.conf"
scp @SSH_OPTS -r "$PROJECT_ROOT\monitoring"                 "root@${MANAGER_IP}:/opt/minitwit/monitoring"

Write-Host "Writing environment file..."
ssh @SSH_OPTS "root@$MANAGER_IP" @"
cat > /opt/minitwit/.env << 'EOF'
DATABASE_PATH=postgresql://minitwit_user:$DB_PASS@$DB_IP/minitwit
SIMULATOR_AUTH=$SIMULATOR_AUTH
EOF
"@

Write-Host "Setting up swarm network..."
ssh @SSH_OPTS "root@$MANAGER_IP" "docker swarm init --advertise-addr $MANAGER_IP 2>/dev/null || true"
ssh @SSH_OPTS "root@$MANAGER_IP" "docker network create --driver overlay --attachable minitwit-network 2>/dev/null || true"

Write-Host "Deploying MiniTwit stack..."
ssh @SSH_OPTS "root@$MANAGER_IP" "cd /opt/minitwit && set -a && . ./.env && docker stack deploy -c docker-compose.yml minitwit"

Write-Host "Deploying monitoring stack..."
ssh @SSH_OPTS "root@$MANAGER_IP" "cd /opt/minitwit && docker stack deploy -c docker-compose.monitoring.yml monitoring"

Write-Host ""
Write-Host "Services:"
ssh @SSH_OPTS "root@$MANAGER_IP" "docker service ls"

Write-Host ""
Write-Host "MiniTwit is available at:"
Write-Host "http://$MANAGER_IP"