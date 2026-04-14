package main

import (
	"devops/minitwit/internal/src"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	_ = godotenv.Load()

	database := minitwit.Connect_db()

	router := mux.NewRouter()
	router.Use(minitwit.AuthMiddleware)
	minitwit.RegisterRoutes(router, database)

	router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))),
	)

	log.Info().Msg("Web server starting on :5000")
	if err := http.ListenAndServe(":5000", router); err != nil {
		log.Fatal().Err(err).Msg("Web server failed to start")
	}
}
