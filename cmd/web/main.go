package main

import (
	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/web"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	godotenv.Load()
	router := mux.NewRouter()
	router.Use(auth.AuthMiddleware)

	web.RegisterRoutes(router)

	router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))),
	)

	if err := http.ListenAndServe(":5000", router); err != nil {
		log.Fatal().Err(err).Msg("Web server failed to start")
	}
}
