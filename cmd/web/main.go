package main

import (
	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/web"
	"net/http"

	"github.com/joho/godotenv"

	"github.com/gorilla/mux"
)

func main() {
	godotenv.Load()
	router := mux.NewRouter()
	router.Use(auth.AuthMiddleware)

	web.RegisterRoutes(router)

	router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))),
	)

	http.ListenAndServe(":5000", router)
}
