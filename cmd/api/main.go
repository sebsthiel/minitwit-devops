package main

import (
	"net/http"

	"devops/minitwit/internal/api"
	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/db"
	"devops/minitwit/internal/services"

	"github.com/gorilla/mux"
)

func main() {
	database := db.Connect()

	services.SetDB(database)
	auth.SetDB(database)

	router := mux.NewRouter()
	router.Use(auth.AuthMiddleware)

	api.RegisterRoutes(router, database)

	http.ListenAndServe(":5001", router)
}