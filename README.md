# MiniTwit DevOps
 
A Go reimplementation of the *MiniTwit* application, built for the **DevOps** course at ITU. The app is split into a web service and a REST API, runs on Docker Swarm with a PostgreSQL backend, and is provisioned on DigitalOcean using Vagrant.
 
## Tech Stack
 
Go 1.25 · PostgreSQL · Docker Swarm · nginx · Prometheus + Grafana + Loki · Vagrant + DigitalOcean · GitHub Actions
 
## Repository Layout
 
```
cmd/api, cmd/web        # Service entry points
internal/               # Handlers, DB access, monitoring
templates/, static/     # Web UI
test/                   # Simulator + API tests
monitoring/             # Prometheus, Grafana, Loki configs
python_implementation/  # Original Python version (reference only)
```
 
## Run Locally
 
Requires Go 1.25+.
 
```bash
go mod tidy
cp minitwit.db /tmp/        # optional: seed with sample data
go run ./cmd/web            # web UI on http://localhost:5000
go run ./cmd/api            # API on  http://localhost:5001/api
```
 
To reset the database, run `rm /tmp/minitwit.db`.
 
## Run with Docker Swarm
 
Requires Docker with Swarm mode and the Compose plugin.
 
```bash
set -a && source .env && set +a   # load env vars
make runlocalswarm                # build images, init swarm, deploy
make deploymonitoring             # optional: Prometheus + Grafana + Loki
make clean                        # tear everything down
```
 
The app is then available at **http://localhost** behind nginx. Grafana is on **http://localhost:3000** (default `admin`/`admin`).
 
### Environment variables
 
| Variable | Description |
| --- | --- |
| `DATABASE_PATH` | Postgres connection string |
| `LOG_LEVEL` | `debug`, `info`, `warn`, or `error` |
| `SIMULATOR_AUTH` | Bearer token for the simulator endpoints |
 
## Testing
 
```bash
python3 minitwit_simulator.py http://localhost:5001/api   # run the simulator
cd test && pytest minitwit_sim_api_test.py                # API integration tests
make all                                                  # lint + static analysis
```
 
## Deploy to Production
 
Production runs on two DigitalOcean droplets (app + db), provisioned with Vagrant.
 
1. Create a DigitalOcean Personal Access Token (Write scope).
2. Generate an SSH key and add the public key to your DigitalOcean account:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/do_vagrant -C "do-vagrant"
   ```
3. Export the required env vars:
   ```bash
   export DIGITAL_OCEAN_TOKEN="dop_v1_..."
   export DIGITAL_OCEAN_SSH_KEY_PATH="$HOME/.ssh/do_vagrant"   # optional
   export DIGITAL_OCEAN_SSH_KEY_NAME="do-vagrant"              # optional
   ```
4. Bring up the droplets:
   ```bash
   vagrant up --provider=digital_ocean
   ```
 
## Contributing
 
We use a feature-branch workflow with mandatory PR review.
 
1. Branch off `develop`: `git checkout -b feat/<short-description>`.
2. Run `make all` and `go test ./...` before pushing.
3. Open a PR into `develop`. CI must be green before merge.
4. Releases to production happen via PR from `develop` → `main`, which triggers the deploy workflow in `.github/workflows/cicd-prod.server.yml`.
## Authors
 
Developed by — ITU DevOps course, Autumn 2025.
- Jacob Sonne
- Renate Mekere
- Adam Nørgård Aabye
- Marc David Paget
-  Sebastian Thiel Steensgaard
- Asger Engelund Trads