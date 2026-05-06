$ErrorActionPreference = "Stop"

$SSH_KEY = "$env:USERPROFILE\.ssh\minitwit_do"
$SSH_OPTS = @("-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-i", $SSH_KEY)

$DB_IP = "104.248.247.141"
$MANAGER_IP = "157.230.121.187"

$DB_PASS = "minitwitpw123"
$SIMULATOR_AUTH = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

Write-Host "Deploying MiniTwit infrastructure..."

Write-Host "Creating folder on manager..."
ssh @SSH_OPTS "root@$MANAGER_IP" "mkdir -p /opt/minitwit"

Write-Host "Copying files to manager..."
scp @SSH_OPTS .\docker-compose.yml "root@${MANAGER_IP}:/opt/minitwit/docker-compose.yml"
scp @SSH_OPTS .\nginx.conf "root@${MANAGER_IP}:/opt/minitwit/nginx.conf"

Write-Host "Setting up swarm network..."
ssh @SSH_OPTS "root@$MANAGER_IP" "docker swarm init --advertise-addr $MANAGER_IP 2>/dev/null || true"
ssh @SSH_OPTS "root@$MANAGER_IP" "docker network create --driver overlay --attachable minitwit-network 2>/dev/null || true"

Write-Host "Writing environment file..."
ssh @SSH_OPTS "root@$MANAGER_IP" "printf '%s\n' 'DATABASE_PATH=postgresql://minitwit_user:$DB_PASS@$DB_IP/minitwit' `"SIMULATOR_AUTH='$SIMULATOR_AUTH'`" > /opt/minitwit/.env"

Write-Host "Deploying stack..."
ssh @SSH_OPTS "root@$MANAGER_IP" "cd /opt/minitwit && set -a && . ./.env && docker stack deploy -c docker-compose.yml minitwit"

Write-Host "Services:"
ssh @SSH_OPTS "root@$MANAGER_IP" "docker service ls"

Write-Host ""
Write-Host "MiniTwit should be available at:"
Write-Host "http://$MANAGER_IP"