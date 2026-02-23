package main

import (
	"devops/minitwit/api_models"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

const simulatorAuth = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

var latest = 0

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

func getQueryInt(r *http.Request, key string, defaultVal int) (int, error) {
	// Get value from query.
	valStr := r.URL.Query().Get(key)

	// If the value doesnt exist return defauly value and nil
	if valStr == "" {
		return defaultVal, nil
	}

	// Convert the value to int.
	return strconv.Atoi(valStr)
}

func APILatest(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetMessages(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIPostFollows(w http.ResponseWriter, r *http.Request) {
	// Get variables
	vars := mux.Vars(r)
	username := vars["username"]
	newLatest, _ := getQueryInt(r, "latest", -1)
	if newLatest != -1 {
		latest = newLatest
	}

	// Decode the requestBody
	var action api_models.FollowAction
	err := json.NewDecoder(r.Body).Decode(&action)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Get user_id and handle user not existing.
	// 404 http.NotFound() user not found Should this be used for follow and unfollow or only username?
	userId := get_user_id(username)
	if userId == "" {
		writeJSON(w, http.StatusNotFound, "User not found (no response body)")
		return
	}

	// Insert or delete from database depending on follow or unfollow.
	if action.Follow != "" {
		followId := get_user_id(action.Follow)
		database.Exec("INSERT INTO follower (who_id, whom_id) VALUES (?, ?)", userId, followId)
	} else if action.Unfollow != "" {
		unfollowId := get_user_id(action.Unfollow)
		database.Exec("DELETE FROM follower WHERE who_id = ? AND whom_id = ?", userId, unfollowId)
	} else {
		// This shouldnt happen because that means an empty FollowAction.
	}

	// 204 no content "success"
	writeJSON(w, http.StatusNoContent, "No Content")
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

func APIRegister(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
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
