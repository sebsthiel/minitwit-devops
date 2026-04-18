package main

import (
	"net/http"
	"os"

	minitwit "devops/minitwit/internal/src"

	"devops/minitwit/internal/monitoring"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

func main() {

	monitoring.Init()

	// Initialize logging
	minitwit.StartLogging()

	database := minitwit.Connect_db()

	simulatorAuth := os.Getenv("SIMULATOR_AUTH")
	if simulatorAuth == "" {
		log.Fatal().Msg("SIMULATOR_AUTH environment variable not set")
	}

	minitwit.SetSimAuth(simulatorAuth)

	router := mux.NewRouter()
	minitwit.RegisterAPIRoutes(router, database)

	router.Handle("/metrics", promhttp.Handler())
	router.Use(monitoring.MetricsMiddleware)

	log.Info().Msg("API server starting on :5001")
	if err := http.ListenAndServe(":5001", router); err != nil {
		log.Fatal().Err(err).Msg("API server failed to start")
	}
}
