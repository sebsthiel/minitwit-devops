package main

import (
	"devops/minitwit/api_models"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

const simulatorAuth = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

// uses the write and encodes the value
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func SimulationAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		if reader.Header.Get("Authorization") != simulatorAuth {
			writeJSON(writer, http.StatusForbidden, api_models.ErrorResponse{
				Status:   http.StatusForbidden,
				ErrorMsg: "You are not authorized to use this resource!",
			})
			return
		}
		next.ServeHTTP(writer, reader)
	})
}

func APILatest(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetMessages(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIPostFollows(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetFollows(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIPostMessageByUser(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetMessagesByUser(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Pwd      string `json:"pwd"`
}

func APIRegister(w http.ResponseWriter, r *http.Request) {

	var req RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username := req.Username
	email := req.Email
	firstPassword := req.Pwd
	secondPassword := firstPassword

	data := Data{}

	ok, registerError := ValidateRegister(username, email, firstPassword, secondPassword)

	// TODO find fitting error code
	data.Error = registerError
	if !ok {
		print("error 1")
		writeJSON(w, 501, registerError)
		return
	}

	pwHash, err := HashPassword(firstPassword)

	_, err = database.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)",
		username, email, pwHash)
	if err != nil {
		print(err.Error())
		data = Data{Error: "Failed to register: " + err.Error(), FormUsername: username}
		// TODO find fitting error code
		writeJSON(w, 501, data)
		return
	}

	writeJSON(w, 200, "User registered succesfully")
}

func RegisterAPIRoutes(r *mux.Router) {

	api_router := r.PathPrefix("/api").Subrouter()

	// requires no auth:
	api_router.HandleFunc("/latest", APILatest).Methods("GET")

	api_router.HandleFunc("/register", APIRegister).Methods("POST")

	// protected_api_router - requires auth
	protected_api_router := api_router.NewRoute().Subrouter()
	protected_api_router.Use(SimulationAuthMiddleware)

	protected_api_router.HandleFunc("/msgs", APIGetMessages).Methods("GET")
	protected_api_router.HandleFunc("/msgs/{username}", APIGetMessagesByUser).Methods("GET")
	protected_api_router.HandleFunc("/msgs/{username}", APIPostMessageByUser).Methods("POST")

	protected_api_router.HandleFunc("/fllws/{username}", APIGetFollows).Methods("GET")
	protected_api_router.HandleFunc("/fllws/{username}", APIPostFollows).Methods("POST")

}
