package main

import (
	"net/http"
	"os"

	"devops/minitwit/internal/src"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	_ = godotenv.Load()

	database := minitwit.Connect_db()

	simulatorAuth := os.Getenv("SIMULATOR_AUTH")
	if simulatorAuth == "" {
		log.Fatal().Msg("SIMULATOR_AUTH environment variable not set")
	}

	router := mux.NewRouter()
	minitwit.RegisterAPIRoutes(router, database)

	log.Info().Msg("API server starting on :5001")
	if err := http.ListenAndServe(":5001", router); err != nil {
		log.Fatal().Err(err).Msg("API server failed to start")
	}
}