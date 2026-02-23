package main

import (
	"devops/minitwit/api_models"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

const simulatorAuth = "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

var latest = -1

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

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetFollows(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIPostMessageByUser(w http.ResponseWriter, r *http.Request) {

	writeJSON(w, 501, "Not implemented yet")
}

func APIGetMessagesByUser(w http.ResponseWriter, r *http.Request) {
	// Get variables from request.
	vars := mux.Vars(r)
	username := vars["username"]
	userId := get_user_id(username)
	if userId == "" {
		writeJSON(w, http.StatusNotFound, "User not found (no response body)")
	}
	newLatest, _ := getQueryInt(r, "latest", -1)
	if newLatest != -1 {
		latest = newLatest
	}
	no, _ := getQueryInt(r, "no", 100)

	// Query messages from db.
	messageRows, _ := query_db(
		`SELECT text, pub_date
		FROM message
		WHERE author_id = ?
		ORDER BY pub_date DESC
		LIMIT ?`,
		userId,
		no,
	)

	// Convert messages (map) into []Message.
	messages := make([]api_models.Message, 0, len(messageRows))
	for _, row := range messageRows {
		text := row["text"].(string)
		pubdate := row["pub_date"].(int64)

		messages = append(messages, api_models.Message{
			Content: text,
			PubDate: time.Unix(pubdate, 0).Format(time.RFC3339),
			User:    username,
		})
	}

	// return response.
	writeJSON(w, http.StatusOK, messages)
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
