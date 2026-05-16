# MiniTwit DevOps

A Go reimplementation of the *MiniTwit* application, built for the **DevOps** course at ITU. The app is split into a web service and a REST API, runs on Docker Swarm with a PostgreSQL backend, and is deployed on DigitalOcean via GitHub Actions.

## Tech Stack

Go 1.25 · PostgreSQL · Docker Swarm · nginx · Prometheus + Grafana + Loki · GitHub Actions

## Repository Layout

```
cmd/api, cmd/web        # Service entry points
internal/               # Handlers, DB access, monitoring
templates/, static/     # Web UI
test/                   # Simulator + API tests
monitoring/             # Prometheus, Grafana, Loki configs
python_implementation/  # Original Python version (reference only)
```

## Run with Docker Swarm

Requires Docker with Swarm mode.

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
| `DISCORD_WEBHOOK_URL` | Url link to discord webhook for availability notifications |

## Testing

```bash
python3 minitwit_simulator.py http://localhost:5001/api   # run the simulator
cd test && pytest minitwit_sim_api_test.py                # API integration tests
make all                                                  # lint + static analysis
```

## Deploy to Production

Production is deployed **automatically via GitHub Actions** — there is no manual deploy step.

Merging a PR from `develop` into `main` triggers the CI/CD pipeline (`.github/workflows/cicd-prod.server.yml`), which:

1. Runs static analysis and tests
2. Builds and pushes the API and web Docker images to Docker Hub
3. SSHs into the swarm manager droplet and runs `docker stack deploy`

Production runs on two DigitalOcean droplets (swarm manager + db) that are already provisioned. The pipeline requires the following GitHub secrets to be set:

| Secret | Description |
| --- | --- |
| `DOCKER_USERNAME` | Docker Hub username |
| `DOCKER_PASSWORD` | Docker Hub password |
| `SSH_HOST_SWARM` | IP address of the swarm manager droplet |
| `SSH_USER_SWARM` | SSH username (e.g. `root`) |
| `SSH_KEY_SWARM` | Private SSH key for the swarm manager |

## Infrastructure

Production runs on two DigitalOcean droplets:

| Droplet | IP | Role |
| --- | --- | --- |
| swarm-manager | 157.230.121.187 | Runs Docker Swarm, nginx, app services, monitoring |
| db | 104.248.247.141 | Runs PostgreSQL 14 |

Access is via SSH key only. The swarm manager can also be reached via the DigitalOcean web console.

## Contributing

We use a feature-branch workflow with mandatory PR review.

1. Branch off `develop`: `git checkout -b <short-description>`.
2. Run `make all` and `go test ./...` before pushing.
3. Open a PR into `develop`. CI must be green before merge.
4. Releases to production happen via PR from `develop` → `main`, which triggers the deploy workflow in `.github/workflows/cicd-prod.server.yml`.

## Authors

Developed by — ITU DevOps course, Autumn 2025.
- Jacob Sonne
- Renate Mekere
- Adam Nørgård Aabye
- Marc David Paget
- Sebastian Thiel Steensgaard
- Asger Engelund Trads
