package main

import (
	"net/http"

	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/web"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	_ = godotenv.Load()

	router := mux.NewRouter()
	router.Use(auth.AuthMiddleware)
	web.RegisterRoutes(router)

	router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))),
	)

	log.Info().Msg("Web server starting on :5000")
	if err := http.ListenAndServe(":5000", router); err != nil {
		log.Fatal().Err(err).Msg("Web server failed to start")
	}
}