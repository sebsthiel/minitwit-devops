param(
    [switch]$Apply
)

$ErrorActionPreference = "Stop"

# ── SSH key ──
$SSH_KEY     = "$env:USERPROFILE\.ssh\minitwit_do"
$SSH_KEY_PUB = "$env:USERPROFILE\.ssh\minitwit_do.pub"
$SSH_OPTS    = @("-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-i", $SSH_KEY)

# ── Droplet names (must match exactly what is on DigitalOcean) ──
$DB_NAME      = "db"
$MANAGER_NAME = "swarm-manager"
$WORKER_NAME  = "swarm-worker-1"

# ── Region / size ──
$REGION = "fra1"
$SIZE   = "s-1vcpu-1gb"
$IMAGE  = "ubuntu-22-04-x64"

# ── App secrets ──
$DB_PASS        = "minitwitpw123"
$DB_USER        = "minitwit_user"
$DB_NAME_PG     = "minitwit"
$SIMULATOR_AUTH = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

Write-Host ""
Write-Host "MiniTwit Infrastructure Provisioning"
Write-Host ""
Write-Host "This script will:"
Write-Host "- Create database droplet"
Write-Host "- Create swarm manager"
Write-Host "- Create swarm worker"
Write-Host "- Install PostgreSQL on DB droplet"
Write-Host "- Restore database backup"
Write-Host "- Install Docker on manager + worker"
Write-Host "- Initialize Docker Swarm"
Write-Host "- Join worker to swarm"
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

# ── Helper: wait for SSH to be ready ──
function Wait-ForSSH {
    param([string]$IP)
    Write-Host "  Waiting for SSH on $IP ..."
    $deadline = (Get-Date).AddSeconds(180)
    while ((Get-Date) -lt $deadline) {
        $result = ssh @SSH_OPTS -o "ConnectTimeout=5" "root@$IP" "echo ok" 2>$null
        if ($result -eq "ok") { Write-Host "  SSH ready on $IP"; return }
        Start-Sleep -Seconds 6
    }
    throw "SSH on $IP never became ready"
}

# ── Create droplets ──
Write-Host ""
Write-Host "Creating database droplet..."
doctl compute droplet create $DB_NAME `
    --size $SIZE --image $IMAGE --region $REGION `
    --ssh-keys $SSH_KEY_PUB --wait

Write-Host ""
Write-Host "Creating swarm manager..."
doctl compute droplet create $MANAGER_NAME `
    --size $SIZE --image $IMAGE --region $REGION `
    --ssh-keys $SSH_KEY_PUB --wait

Write-Host ""
Write-Host "Creating swarm worker..."
doctl compute droplet create $WORKER_NAME `
    --size $SIZE --image $IMAGE --region $REGION `
    --ssh-keys $SSH_KEY_PUB --wait

# ── Get IPs automatically ──
Write-Host ""
Write-Host "Getting droplet IPs..."
$DB_IP      = (doctl compute droplet list $DB_NAME      --format PublicIPv4 --no-header).Trim()
$MANAGER_IP = (doctl compute droplet list $MANAGER_NAME --format PublicIPv4 --no-header).Trim()
$WORKER_IP  = (doctl compute droplet list $WORKER_NAME  --format PublicIPv4 --no-header).Trim()

Write-Host "  DB      : $DB_IP"
Write-Host "  Manager : $MANAGER_IP"
Write-Host "  Worker  : $WORKER_IP"

# ── Wait for SSH on all 3 ──
Wait-ForSSH $DB_IP
Wait-ForSSH $MANAGER_IP
Wait-ForSSH $WORKER_IP

# ── Install PostgreSQL on DB droplet ──
Write-Host ""
Write-Host "Installing PostgreSQL on DB droplet..."
$PG_SETUP = @"
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q postgresql postgresql-contrib
echo "listen_addresses = '*'" >> /etc/postgresql/*/main/postgresql.conf
echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/*/main/pg_hba.conf
systemctl enable postgresql
systemctl restart postgresql
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME_PG OWNER $DB_USER;"
echo "PostgreSQL ready."
"@
ssh @SSH_OPTS "root@$DB_IP" $PG_SETUP
Write-Host "PostgreSQL installed."

# ── Restore database backup ──
Write-Host ""
Write-Host "Restoring database backup..."
if (Test-Path ".\backup\minitwit.pgdump") {
    Get-Content -AsByteStream ".\backup\minitwit.pgdump" | `
        ssh @SSH_OPTS "root@$DB_IP" `
        "sudo -u postgres pg_restore -d minitwit -Fc --no-owner --role=minitwit_user"
    Write-Host "Database restored."
} else {
    Write-Host "WARNING: No backup file found at .\backup\minitwit.pgdump"
    Write-Host "Skipping restore - database will be empty."
    Write-Host "If you need your data, stop now and run backup-database.ps1 first."
}

# ── Install Docker on manager + worker ──
Write-Host ""
Write-Host "Installing Docker on swarm nodes..."
$DOCKER_INSTALL = @"
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q ca-certificates curl gnupg lsb-release haveged
systemctl enable --now haveged
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y -q
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
echo "Docker ready."
"@
foreach ($node in @($MANAGER_IP, $WORKER_IP)) {
    Write-Host "  Installing Docker on $node ..."
    ssh @SSH_OPTS "root@$node" $DOCKER_INSTALL
}
Write-Host "Docker installed on both nodes."

# ── Init Docker Swarm ──
Write-Host ""
Write-Host "Initializing Docker Swarm..."
ssh @SSH_OPTS "root@$MANAGER_IP" "docker swarm init --advertise-addr $MANAGER_IP 2>/dev/null || true"
ssh @SSH_OPTS "root@$MANAGER_IP" "docker network create --driver overlay --attachable minitwit-network 2>/dev/null || true"

$JOIN_TOKEN = (ssh @SSH_OPTS "root@$MANAGER_IP" "docker swarm join-token worker -q").Trim()
ssh @SSH_OPTS "root@$WORKER_IP" "docker swarm join --token $JOIN_TOKEN ${MANAGER_IP}:2377 2>/dev/null || true"

Write-Host "Swarm nodes:"
ssh @SSH_OPTS "root@$MANAGER_IP" "docker node ls"

# ── Save IPs so deploy-existing.ps1 can read them ──
Write-Host ""
Write-Host "Saving IPs for deploy step..."
@"
`$DB_IP      = "$DB_IP"
`$MANAGER_IP = "$MANAGER_IP"
`$WORKER_IP  = "$WORKER_IP"
"@ | Set-Content "$PSScriptRoot\infrastructure-ips.ps1"

Write-Host ""
Write-Host "Infrastructure creation complete."
Write-Host ""
Write-Host "DB IP      : $DB_IP"
Write-Host "Manager IP : $MANAGER_IP"
Write-Host "Worker IP  : $WORKER_IP"
Write-Host ""
Write-Host "Now run:"
Write-Host ".\scripts\deploy-existing.ps1"