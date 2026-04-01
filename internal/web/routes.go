package web

import "github.com/gorilla/mux"

func RegisterRoutes(router *mux.Router) {

	router.HandleFunc("/", MyTimeline).Methods("GET")

	router.HandleFunc("/public", Timeline).Methods("GET")

	router.HandleFunc("/add_message", AddMessage).Methods("POST")

	router.HandleFunc("/login", Login).Methods("GET", "POST")

	router.HandleFunc("/logout", Logout)

	router.HandleFunc("/register", Register).Methods("GET", "POST")

	router.HandleFunc("/{username}/follow", FollowUser).Methods("GET")

	router.HandleFunc("/{username}/unfollow", UnfollowUser).Methods("GET")

	router.HandleFunc("/{username}", UserTimeline).Methods("GET")
}
