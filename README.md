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

# Run application using docker:

Create docker image:
```bash
docker build -f Dockerfile -t minitwit-app . 
```
 
Start minitwit (using docker):
```bash
docker compose up
```

Stop minitwit (using docker):
```bash
docker compose down
```


# Simulation API OPENAPI version
NOTE: We are currently not using this. We are moving away from OPENAPI to just have it in the same application.
To run the simulation api:

```bash
cd minitwit_sim_api
go mod tidy
go run main.go
```

If you get the error that /tmp/minitwit.db is missing, run the minitwit application first. (This will initialize an empty database file)


