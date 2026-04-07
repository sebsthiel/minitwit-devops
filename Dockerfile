FROM golang:1.25

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

#Build API
RUN CGO_ENABLED=1 GOOS=linux go build -o api ./cmd/api

#Build WEB
RUN CGO_ENABLED=1 GOOS=linux go build -o web ./cmd/web

EXPOSE 5000
EXPOSE 5001