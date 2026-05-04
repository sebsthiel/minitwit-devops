$ErrorActionPreference = "Stop"

$SSH_KEY = "$env:USERPROFILE\.ssh\minitwit_do"
$DB_IP = "104.248.247.141"
$MANAGER_IP = "157.230.121.187"

$DB_PASS = "minitwitpw123"
$SIMULATOR_AUTH = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

Write-Host "Deploying MiniTwit infrastructure..."

Write-Host "Creating folder on manager..."
ssh -i $SSH_KEY "root@$MANAGER_IP" "mkdir -p /opt/minitwit"

Write-Host "Copying files to manager..."
scp -i $SSH_KEY .\docker-compose.yml "root@${MANAGER_IP}:/opt/minitwit/docker-compose.yml"
scp -i $SSH_KEY .\nginx-http.conf "root@${MANAGER_IP}:/opt/minitwit/nginx.conf"

Write-Host "Setting up swarm network..."
ssh -i $SSH_KEY "root@$MANAGER_IP" "docker swarm init --advertise-addr $MANAGER_IP || true"
ssh -i $SSH_KEY "root@$MANAGER_IP" "docker network create --driver overlay --attachable minitwit-network || true"

Write-Host "Writing environment file..."
ssh -i $SSH_KEY "root@$MANAGER_IP" "echo DATABASE_PATH=postgresql://minitwit_user:$DB_PASS@$DB_IP/minitwit > /opt/minitwit/.env"
ssh -i $SSH_KEY "root@$MANAGER_IP" "echo SIMULATOR_AUTH='$SIMULATOR_AUTH' >> /opt/minitwit/.env"

Write-Host "Deploying stack..."
ssh -i $SSH_KEY "root@$MANAGER_IP" "cd /opt/minitwit && set -a && . ./.env && docker stack deploy -c docker-compose.yml minitwit"

Write-Host "Services:"
ssh -i $SSH_KEY "root@$MANAGER_IP" "docker service ls"

Write-Host ""
Write-Host "MiniTwit should be available at:"
Write-Host "http://$MANAGER_IP"