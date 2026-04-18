package main

import (
	"devops/minitwit/internal/monitoring"
	minitwit "devops/minitwit/internal/src"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

func main() {

	monitoring.Init()

	minitwit.StartLogging()

	database := minitwit.Connect_db()

	router := mux.NewRouter()
	router.Use(minitwit.AuthMiddleware)
	minitwit.RegisterRoutes(router, database)
	router.Handle("/metrics", promhttp.Handler())
	router.Use(monitoring.MetricsMiddleware)

	router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))),
	)

	log.Info().Msg("Web server starting on :5000")
	if err := http.ListenAndServe(":5000", router); err != nil {
		log.Fatal().Err(err).Msg("Web server failed to start")
	}
}
