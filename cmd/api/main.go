package main

import (
	"net/http"
	"os"

	"devops/minitwit/internal/api"
	"devops/minitwit/internal/db"
	"devops/minitwit/internal/services"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	_ = godotenv.Load()

	database := db.Connect()
	services.SetDB(database)

	simulatorAuth := os.Getenv("SIMULATOR_AUTH")
	if simulatorAuth == "" {
		log.Fatal().Msg("SIMULATOR_AUTH environment variable not set")
	}

	router := mux.NewRouter()
	api.RegisterRoutes(router, database)

	log.Info().Msg("API server starting on :5001")
	if err := http.ListenAndServe(":5001", router); err != nil {
		log.Fatal().Err(err).Msg("API server failed to start")
	}
}