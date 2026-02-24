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
				ErrorMsg: "Unauthorized - Must include correct Authorization header",
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

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetFollows(w http.ResponseWriter, r *http.Request) {

	// Access variables:
	vars := mux.Vars(r)
	username := vars["username"]
	newLatest, _ := getQueryInt(r, "latest", -1)
	no, _ := getQueryInt(r, "no", 100)

	// Update latest if it is in the request.
	if newLatest != -1 {
		latest = newLatest
	}

	// Get user and handle if user doesnt exist.
	userIdRow, userIdErr := query_db_one("SELECT user_id FROM user WHERE username = ?", username)
	if userIdErr != nil || len(userIdRow) == 0 {
		writeJSON(w, http.StatusNotFound, "User not found (no response body)")
		return
	}

	userId := userIdRow["user_id"].(int64)

	// Get usernames of users who follow the user.
	followers, _ := query_db(
		`SELECT u.username
		FROM follower f
		JOIN user u ON f.whom_id = u.user_id
		WHERE f.who_id = ?
		LIMIT ?`,
		userId,
		no,
	)

	// Convert the map into a []string.
	var req api_models.FollowsResponse
	for _, row := range followers {
		if username, ok := row["username"].(string); ok {
			req.Follows = append(req.Follows, username)
		}
	}

	// return the response
	writeJSON(w, http.StatusOK, req)
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
