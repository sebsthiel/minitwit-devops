package minitwit

import (
	"devops/minitwit/api_models"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var simulatorAuth string

const userNotFoundMsg = "User not found (no response body)"

var latest = -1

// uses the write and encodes the value
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func SetSimAuth(simAuth string){
	simulatorAuth = simAuth
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
	if latest == -1 {
		writeJSON(w, http.StatusInternalServerError, api_models.ErrorResponse{Status: http.StatusInternalServerError, ErrorMsg: "Internal Server Error"})
		return
	}

	var response api_models.LatestValue
	response.Latest = int32(latest)
	writeJSON(w, http.StatusOK, response)
}

func APIGetMessages(w http.ResponseWriter, r *http.Request) {
	// Get variables from request.
	newLatest, _ := getQueryInt(r, "latest", -1)
	if newLatest != -1 {
		latest = newLatest
	}
	no, _ := getQueryInt(r, "no", 100)

	// Query messages from db.
	var messageRows []map[string]any

	res := database.
		Table("message AS m").
		Select("u.username, m.text, m.pub_date").
		Joins(`JOIN "user" u ON m.author_id = u.user_id`).
		Order("m.pub_date DESC").
		Limit(no).
		Find(&messageRows)

	if res.Error != nil {
		log.Warn().Stack().Err(res.Error).Msg("")
		return
	}

	// Convert messages (map) into []Message.
	messages := make([]api_models.Message, 0, len(messageRows))
	for _, row := range messageRows {
		username := row["username"].(string)
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
		log.Warn().Caller().Msg("RequestBody has Invalid JSON")
		writeJSON(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	log.Info().Caller().Interface("action", action)

	// Get user_id and handle user not existing.
	// 404 http.NotFound() user not found Should this be used for follow and unfollow or only username?
	userId := get_user_id(username)
	if userId == -1 {
		log.Warn().Caller().Str("username", username).Msg(userNotFoundMsg)
		writeJSON(w, http.StatusNotFound, userNotFoundMsg)
		return
	}

	// Insert or delete from database depending on follow or unfollow.
	if action.Follow != "" {
		followId := get_user_id(action.Follow)
		if followId != -1 {
			database.Create(&Follower{
				Who_id:  userId,
				Whom_id: followId,
			})
		} else {
			log.Warn().Caller().Str("followUsername", action.Follow).Msg("Could not find user to follow. User not found (no response body)")
			writeJSON(w, http.StatusNotFound, userNotFoundMsg)
			return
		}
	} else if action.Unfollow != "" {
		unfollowId := get_user_id(action.Unfollow)
		database.Where("who_id = ? AND whom_id = ?", userId, unfollowId).Delete(&Follower{})
		log.Info().Caller().Int("userId", userId).Int("followId", unfollowId).Msg("Unfollowed")
	} else {
		// This shouldnt happen because that means an empty FollowAction.
		log.Warn().Caller().Msg("This shouldnt happen because that means an empty FollowAction")
	}

	// 204 no content "success"
	log.Info().Int("HTTP_StatusCode", http.StatusNoContent).Msg("No Content")
	writeJSON(w, http.StatusNoContent, "No Content")
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
	var user User
	res := database.First(&user, "username = ?", username)

	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			log.Info().Caller().Str("username", username).Msg(userNotFoundMsg)
			writeJSON(w, http.StatusNotFound, userNotFoundMsg)
			return
		}
		log.Warn().Stack().Err(res.Error).Msg("")
		return
	}

	var followers []map[string]any

	res = database.
		Table("follower AS f").
		Select("u.username").
		Joins(`JOIN "user" u ON f.whom_id = u.user_id`).
		Where("f.who_id = ?", user.User_id).
		Limit(no).
		Find(&followers)

	if res.Error != nil {
		log.Warn().Stack().Err(res.Error).Msg("")
	}

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
	// Get variables from request.
	vars := mux.Vars(r)
	username := vars["username"]
	userId := get_user_id(username)
	if userId == -1 {
		log.Info().Caller().Str("username", username).Msg(userNotFoundMsg)
		writeJSON(w, http.StatusNotFound, userNotFoundMsg)
		return
	}
	newLatest, _ := getQueryInt(r, "latest", -1)
	if newLatest != -1 {
		latest = newLatest
	}

	// Decode PostMessage from request
	var req api_models.PostMessage
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Warn().Caller().Msg("Invalid JSON")
		writeJSON(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Add message to the database
	database.Create(&Message{
		Author_id: userId,
		Text:      req.Content,
		Pub_date:  int(time.Now().Unix()),
		Flagged:   0,
	})
	// return response.
	writeJSON(w, http.StatusNoContent, "No Content")
}

func APIGetMessagesByUser(w http.ResponseWriter, r *http.Request) {
	// Get variables from request.
	vars := mux.Vars(r)
	username := vars["username"]
	userId := get_user_id(username)
	if userId == -1 {
		log.Info().Caller().Str("username", username).Msg(userNotFoundMsg)
		writeJSON(w, http.StatusNotFound, userNotFoundMsg)
	}
	newLatest, _ := getQueryInt(r, "latest", -1)
	if newLatest != -1 {
		latest = newLatest
	}
	no, _ := getQueryInt(r, "no", 100)

	// Query messages from db.
	var messageRows []map[string]any

	res := database.
		Table("message").
		Select("text, pub_date").
		Where("author_id = ?", userId).
		Order("pub_date DESC").
		Limit(no).
		Find(&messageRows)

	if res.Error != nil {
		log.Warn().Stack().Int("author_id", userId).Int("limit_number", no).Err(res.Error).Msg("")
	}

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

	var req api_models.RegisterRequest

	errorResponse := api_models.ErrorResponse{
		Status:   http.StatusBadRequest,
		ErrorMsg: "Invalid JSON",
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Warn().Caller().Int("HTTP_StatusCode", int(errorResponse.Status)).Msg(errorResponse.ErrorMsg)
		writeJSON(w, int(errorResponse.Status), errorResponse)
		return
	}

	newLatest, _ := getQueryInt(r, "latest", -1)
	if newLatest != -1 {
		latest = newLatest
	}

	username := req.Username
	email := req.Email
	firstPassword := req.Pwd
	secondPassword := firstPassword

	errorResponse.Status = http.StatusInternalServerError

	ok, registerError := ValidateRegister(username, email, firstPassword, secondPassword)

	errorResponse.ErrorMsg = registerError
	if !ok {
		log.Warn().Caller().Int("HTTP_StatusCode", int(errorResponse.Status)).Msg(errorResponse.ErrorMsg)
		writeJSON(w, int(errorResponse.Status), errorResponse)
		return
	}

	pwHash, _ := HashPassword(firstPassword)

	user := User{
		Username: username,
		Email:    email,
		Pw_hash:  pwHash,
	}

	res := database.Create(&user)
	if res.Error != nil {
		errorResponse.ErrorMsg = "Failed to register: " + res.Error.Error()
		log.Warn().Caller().Int("HTTP_StatusCode", int(errorResponse.Status)).Msg(errorResponse.ErrorMsg)
		writeJSON(w, int(errorResponse.Status), errorResponse)
		return
	}

	writeJSON(w, http.StatusNoContent, "User registered succesfully")
}

func RegisterAPIRoutes(r *mux.Router, db *gorm.DB) {

	api_router := r.PathPrefix("/api").Subrouter()

	database = db

	// endpoint for health check
	api_router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
    	w.WriteHeader(http.StatusOK)
	})

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
