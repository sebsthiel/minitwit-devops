package web

import (
	"errors"
	"net/http"
	"time"

	"devops/minitwit/api_models"
	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/models"
	"devops/minitwit/internal/services"
	"devops/minitwit/internal/session"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const PER_PAGE = 30

func convertAPIMessagesToTemplateMessages(apiMsgs []api_models.Message) []map[string]any {
	msgs := make([]map[string]any, 0, len(apiMsgs))

	for _, m := range apiMsgs {
		msgs = append(msgs, map[string]any{
			"text":     m.Content,
			"username": m.User,
			"pub_date": 0,
		})
	}

	return msgs
}

var database *gorm.DB

func SetDB(db *gorm.DB) {
	database = db
}

func Login(w http.ResponseWriter, r *http.Request) {
	_, ok := auth.TryGetUserFromRequest(r)
	if ok {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	data := models.Data{
		Error:        "",
		FormUsername: "",
		Flashes:      session.GetFlashes(w, r),
		User:         nil,
	}

	if r.Method == http.MethodGet {
		if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	userUser, errorMessage := services.ValidateLogin(username, password)

	if userUser != nil {
		sessionData, err := session.GetStore().Get(r, "session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		sessionData.Values["user_id"] = userUser.User_id

		err = sessionData.Save(r, w)
		if err != nil {
			http.Error(w, "Could not save session", http.StatusInternalServerError)
			return
		}
		session.AddFlash(w, r, "You were logged in")
		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}

	data.Error = errorMessage
	if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func FollowUser(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.TryGetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	usernameToFollow := vars["username"]

	whomID := services.GetUserID(usernameToFollow)
	if whomID == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	follower := models.Follower{
		Who_id:  user.User_id,
		Whom_id: whomID,
	}

	res := database.Create(&follower)
	if res.Error != nil {
		http.Error(w, "Failed to follow user: "+res.Error.Error(), http.StatusInternalServerError)
		return
	}

	session.AddFlash(w, r, "You are now following \""+usernameToFollow+"\"")
	http.Redirect(w, r, "/"+usernameToFollow, http.StatusSeeOther)
}

func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.TryGetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	usernameToUnfollow := vars["username"]

	whomID := services.GetUserID(usernameToUnfollow)
	if whomID == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	res := database.Where("who_id = ? AND whom_id = ?", user.User_id, whomID).Delete(&models.Follower{})
	if res.Error != nil {
		http.Error(w, "Failed to unfollow user: "+res.Error.Error(), http.StatusInternalServerError)
		return
	}

	session.AddFlash(w, r, "You are no longer following \""+usernameToUnfollow+"\"")
	http.Redirect(w, r, "/"+usernameToUnfollow, http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	sessionData, err := session.GetStore().Get(r, "session")
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	delete(sessionData.Values, "user_id")

	err = sessionData.Save(r, w)
	if err != nil {
		http.Error(w, "could not save session", http.StatusInternalServerError)
		return
	}

	session.AddFlash(w, r, "You were logged out")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func MyTimeline(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.TryGetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	var msgs []map[string]any

	res := database.
		Table("message AS m").
		Select("m.*, u.*").
		Joins(`JOIN "user" u ON m.author_id = u.user_id`).
		Where("m.flagged = 0 AND (u.user_id = ? OR u.user_id IN (?) )",
			user.User_id,
			database.Model(&models.Follower{}).Select("whom_id").Where("who_id = ?", user.User_id),
		).
		Order("m.pub_date DESC").
		Limit(PER_PAGE).
		Find(&msgs)

	if res.Error != nil {
		log.Warn().Stack().Err(res.Error).Msg("Could not load MyTimeline")
		return
	}

	data := models.Data{
		Messages: msgs,
		Endpoint: "timeline",
		User:     &user,
		Flashes:  session.GetFlashes(w, r),
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Warn().Stack().Int("HTTP_StatusCode", http.StatusInternalServerError).Err(err).Msg("Error when ExecuteTemplate for MyTimeline")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func UserTimeline(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	flashes := session.GetFlashes(w, r)

	var messages []map[string]any

	res := database.
		Table("message").
		Select(`message.message_id, message.text, message.pub_date, "user".username`).
		Joins(`JOIN "user" ON "user".user_id = message.author_id`).
		Where(`"user".username = ?`, username).
		Order("message.pub_date DESC").
		Limit(PER_PAGE).
		Scan(&messages)

	if res.Error != nil {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	var profileUser models.User

	res = database.
		Select("user_id, username").
		Where("username = ?", username).
		First(&profileUser)

	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}
	if res.Error != nil {
		log.Warn().Stack().Err(res.Error).Msg("Could not load UserTimeline")
		return
	}

	data := models.Data{
		FormUsername: username,
		ProfileUser:  &profileUser,
		Messages:     messages,
		Endpoint:     "user_timeline",
		Followed:     false,
		Flashes:      flashes,
	}

	user, ok := auth.TryGetUserFromRequest(r)
	if ok {
		data.User = &user
	}

	var follower models.Follower

	res = database.
		Select("whom_id").
		Where("who_id = ? AND whom_id = ?", user.User_id, services.GetUserID(profileUser.Username)).
		First(&follower)

	if res.Error == nil {
		data.Followed = true
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func Timeline(w http.ResponseWriter, r *http.Request) {
	client := NewAPIClient()

	apiMsgs, err := client.GetPublicMessages()
	if err != nil {
		http.Error(w, "Could not load public timeline from API: "+err.Error(), http.StatusBadGateway)
		return
	}

	msgs := convertAPIMessagesToTemplateMessages(apiMsgs)

	data := models.Data{
		Messages: msgs,
		Endpoint: "public_timeline",
		Flashes:  session.GetFlashes(w, r),
	}

	user, ok := auth.TryGetUserFromRequest(r)
	if ok {
		data.User = &user
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := registerTpl.ExecuteTemplate(w, "layout", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	firstPassword := r.FormValue("password")
	secondPassword := r.FormValue("password2")

	data := models.Data{}

	ok, registerError := services.ValidateRegister(username, email, firstPassword, secondPassword)

	data.Error = registerError
	if !ok {
		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	pwHash, err := services.HashPassword(firstPassword)

	user := models.User{
		Username: username,
		Email:    email,
		Pw_hash:  pwHash,
	}

	res := database.Create(&user)
	if res.Error != nil {
		data = models.Data{Error: "Failed to register: " + err.Error(), FormUsername: username}
		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	session.AddFlash(w, r, "You were successfully registered and can login now")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func AddMessage(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.TryGetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	res := database.Create(&models.Message{
		Author_id: user.User_id,
		Text:      r.FormValue("text"),
		Pub_date:  int(time.Now().Unix()),
	})
	if res.Error != nil {
		http.Error(w, "Failed post message: "+res.Error.Error(), http.StatusInternalServerError)
		return
	}

	session.AddFlash(w, r, "Your message was recorded")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}