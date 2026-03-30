package main

import (
	"net/http"

	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/db"
	"devops/minitwit/internal/services"
	"devops/minitwit/internal/web"

	"github.com/gorilla/mux"
)

func main() {
	database := db.Connect()

	web.SetDB(database)
	services.SetDB(database)
	auth.SetDB(database)

	router := mux.NewRouter()
	router.Use(auth.AuthMiddleware)

	web.RegisterRoutes(router)

	router.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))),
	)

	http.ListenAndServe(":5000", router)
}