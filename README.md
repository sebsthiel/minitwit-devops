# Run the application

To synchronize dependencies run:

```bash
go mod tidy
```

You can run it by writing:

```bash
go run .
```

When running you can find it on:
[http://localhost:5001](http://localhost:5001)

## Use an empty database:

To use an empty database you need to simply delete the database folder in the tmp folder.
This can be done like:

```bash
rm /tmp/minitwit.db
```

## Use a database with data

The repository contains a small database file contained with some messages and users.
To make the application use this database you need to copy the minitwit.db from the root folder to the "/tmp" folder on your machine.

```bash
cp minitwit.db /tmp/
```

# Run application using docker Swarm
Load the variables from the .env file into the shell environment:
```bash
set -a && source .env && set +a
```
Then run:
```bash
make runlocalswarm
```
This command is idempotent.
The result should be a swarm of the application that uses a postgresql database. 
If you want to spin up the monitoring stack you can run:
```bash
make deploymonitoring
```
To remove the solution and/or monitoring do:
```bash
make clean
```

You can also do the steps manually if you desire:

## 0. Built local images (for running locally)
Docker swarm does not support building the images using "build" in the compose file. Therefore the local images must be built before deploying the stack:
```bash
# API
docker build -t minitwit-api:dev -f Dockerfile.api .
# Web
docker build -t minitwit-web:dev -f Dockerfile.web .
```

## 1. Initialize the swarm (first time only)
```bash
docker swarm init
```
## 2. Create the shared overlay network (first time only)
```bash
docker network create --driver overlay minitwit-network
```
## 3. Load environment variables
Load the variables from the .env file into the shell environment:
```bash
set -a && source .env && set +a
```
## 4. Deploy the stack (Using local images)
```bash
# API And Web services
docker stack deploy -c docker-compose.develop.yml minitwit
# Monitoring services 
docker stack deploy -c docker-compose.monitoring.yml monitoring
```
## 5. Verify services
```bash
docker service ls
```
## 6. View logs
```bash
## For API
docker service logs minitwit_api
## For Web
docker service logs minitwit_web
```
## 7. Remove the stack
```bash
docker stack rm minitwit
```

# Run application using docker Compose (Depricated, probably doens't work anymore):

The docker commands have been inserted into a Makefile.
To build and run the application with docker:

```bash
make runlocal
```

Stop minitwit (using docker):

```bash
docker compose down
```

# Test application

## Run a minitwit simulator against our API:

```bash
python3 minitwit_simulator.py http://localhost:5001/api
```

## Run

# Simulation API

The API is part of the application. It is accessible on the same host but with the route /api.
See api.go

## Testing the api

This requires two console windows.

```bash
1) Run minitwit
cd /minitwit-devops
run go .

2) Run the minitwit_sim_api_test.py inside the test folder.
cd /minitwit-devops/test
pytest minitwit_sim_api_test.py
```

# Create environment - RUN Vagrant

## Setting Required Environment Variables for Vagrant + DigitalOcean

### 1. DIGITAL_OCEAN_TOKEN (Required)

Create a **Personal Access Token (Write scope)** in:

DigitalOcean → API → Tokens/Keys → Generate New Token

Copy the token (looks like `dop_v1_...`).

#### macOS / Linux (bash/zsh)

Temporary (current terminal only):

```bash
export DIGITAL_OCEAN_TOKEN="dop_v1_..."
```

Persistent (add to ~/.zshrc or ~/.bashrc):

```bash
echo 'export DIGITAL_OCEAN_TOKEN="dop_v1_..."' >> ~/.bashrc
source ~/.bashrc
```

### 2. DIGITAL_OCEAN_SSH_KEY_PATH

If you don’t set it, your Vagrantfile uses ~/.ssh/do_vagrant.

You must have these files on your host:

~/.ssh/do_vagrant (private key)

~/.ssh/do_vagrant.pub (public key)

Create them (recommended):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/do_vagrant -C "do-vagrant"
```

#### If you used a different path, set it:

```bash
export DIGITAL_OCEAN_SSH_KEY_PATH="~/.ssh/some/path"
```

### 3. DIGITAL_OCEAN_SSH_KEY_NAME

This is the name of the SSH key object inside DigitalOcean. Default is do-vagrant.

```bash
export DIGITAL_OCEAN_SSH_KEY_NAME="do-vagrant-myname"
```

### 4. Verify variables are set

```bash
echo $DIGITAL_OCEAN_TOKEN
echo $DIGITAL_OCEAN_SSH_KEY_PATH
echo $DIGITAL_OCEAN_SSH_KEY_NAME
```

## Run vagrant

```bash
vagrant up --provider=digital_ocean
```
