package api

import (
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var database *gorm.DB

func RegisterRoutes(r *mux.Router, db *gorm.DB) {
	database = db
	simulatorAuth = os.Getenv("SIMULATOR_AUTH")
	if simulatorAuth == "" {
		log.Fatal().Msg("SIMULATOR_AUTH environment variable not set")
	}
	apiRouter := r.PathPrefix("/api").Subrouter()

	// no auth
	apiRouter.HandleFunc("/latest", APILatest).Methods("GET")
	apiRouter.HandleFunc("/register", APIRegister).Methods("POST")

	apiRouter.HandleFunc("/login", APILogin).Methods("POST")

	// auth protected
	protectedAPIRouter := apiRouter.NewRoute().Subrouter()
	protectedAPIRouter.Use(SimulationAuthMiddleware)

	protectedAPIRouter.HandleFunc("/msgs", APIGetMessages).Methods("GET")
	protectedAPIRouter.HandleFunc("/msgs/{username}", APIGetMessagesByUser).Methods("GET")
	protectedAPIRouter.HandleFunc("/msgs/{username}", APIPostMessageByUser).Methods("POST")

	protectedAPIRouter.HandleFunc("/fllws/{username}", APIGetFollows).Methods("GET")
	protectedAPIRouter.HandleFunc("/fllws/{username}", APIPostFollows).Methods("POST")
}
