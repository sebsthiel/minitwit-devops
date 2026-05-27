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

### Prerequisites

| Tool | Version | Purpose |
| --- | --- | --- |
| [Docker](https://docs.docker.com/get-docker/) | 20.10+ with Swarm mode | Running the application stack |
| [Python](https://www.python.org/downloads/) | 3.11+ | Running the simulator and API tests |
| [pytest](https://docs.pytest.org/) | Latest | API integration tests |
| [Make](https://www.gnu.org/software/make/) | Any | Running convenience commands |

```bash
make deployall
```

The app is then available at **http://localhost** behind nginx.
Grafana is on **http://localhost:grafana** (default `admin`/`admin`).

To take the solution down run:
```bash
make clean
```

### Environment variables

| Variable | Description |
| --- | --- |
| `DATABASE_PATH` | Postgres connection string |
| `LOG_LEVEL` | `debug`, `info`, `warn`, or `error` |
| `SIMULATOR_AUTH` | Bearer token for the simulator endpoints |
| `DISCORD_WEBHOOK_URL` | Url link to discord webhook for availability notifications |

## Testing

Run the following to run static analysis checks:
```bash
make all                                                  # lint + static analysis
```

To test the api functionality, the solution has to be working. You can test the functionality by running:
```bash
cd test && pytest minitwit_sim_api_test.py                # API integration tests
```

Additionally you can to run the following to host a simulator that will target the solution:
```bash
python3 minitwit_simulator.py http://localhost/api   # run the simulator
```


## Deploying

Production is deployed **automatically via GitHub Actions**

Merging a PR from `develop` into `main` triggers the CI/CD pipeline (`.github/workflows/cicd-prod.server.yml`), which:

1. Runs static analysis and tests
2. Builds and pushes the API and web Docker images to Docker Hub
3. SSHs into the swarm manager droplet and runs `docker stack deploy`

Production runs on three DigitalOcean droplets (swarm manager + db) that are already provisioned. The pipeline requires the following GitHub secrets to be set:

| Secret | Description |
| --- | --- |
| `DOCKER_USERNAME` | Docker Hub username |
| `DOCKER_PASSWORD` | Docker Hub password |
| `SSH_HOST_SWARM` | IP address of the swarm manager droplet |
| `SSH_USER_SWARM` | SSH username (e.g. `root`) |
| `SSH_KEY_SWARM` | Private SSH key for the swarm manager |


## Contributing
We use a feature-branch workflow with mandatory PR review.

1. Branch off `develop`: `git checkout -b <branch-name>`.
2. Run `make all` and `go test ./...` before pushing.
3. Open a PR into `develop`. CI must be green before merge.
4. When merged into main it triggers the deploy workflow in `.github/workflows/cicd-prod.server.yml`.

## Authors

Developed by — ITU DevOps course, Autumn 2025.
- Jacob Sonne
- Renate Mekere
- Adam Nørgård Aabye
- Marc David Paget
- Sebastian Thiel Steensgaard
- Asger Engelund Trads

## License
[MIT](LICENSE)