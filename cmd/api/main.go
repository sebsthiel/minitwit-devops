package main

import (
	"net/http"

	"github.com/joho/godotenv"

	"devops/minitwit/internal/api"
	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/db"
	"devops/minitwit/internal/services"

	"github.com/gorilla/mux"
)

func main() {
	_ = godotenv.Load()
	database := db.Connect()

	services.SetDB(database)

	router := mux.NewRouter()
	router.Use(auth.AuthMiddleware)

	api.RegisterRoutes(router, database)

	http.ListenAndServe(":5001", router)
}
