FROM golang:1.25

WORKDIR /app

# Copy and download go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our Go source code
COPY *.go ./
COPY templates/ ./templates/

RUN CGO_ENABLED=0 GOOS=linux go build -o /minitwit-app

EXPOSE 5001

CMD ["/minitwit-app"]
