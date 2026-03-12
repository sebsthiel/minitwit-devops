FROM golang:1.25

WORKDIR /app

# Install libsqlite3 which is needed for the application
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy and download go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our Go source code
COPY *.go ./
COPY templates/ ./templates/
COPY api_models/ ./api_models/
COPY static/ ./static/

RUN CGO_ENABLED=1 GOOS=linux go build -o /minitwit-app

EXPOSE 5001

CMD ["/minitwit-app"]
