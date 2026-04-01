package web

import (
	"net/http"
	"time"

	"devops/minitwit/api_models"
	"devops/minitwit/internal/auth"
	"devops/minitwit/internal/models"
	"devops/minitwit/internal/session"

	"github.com/gorilla/mux"
)

const PER_PAGE = 30

func convertAPIMessagesToTemplateMessages(apiMsgs []api_models.Message) []map[string]any {

	msgs := make([]map[string]any, 0, len(apiMsgs))

	for _, m := range apiMsgs {

		pubDateUnix := int64(0)

		parsedTime, err := time.Parse(time.RFC3339, m.PubDate)

		if err == nil {
			pubDateUnix = parsedTime.Unix()
		}

		msgs = append(msgs, map[string]any{
			"text":     m.Content,
			"username": m.User,
			"pub_date": pubDateUnix,
		})
	}

	return msgs
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

		loginTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	client := NewAPIClient()

	user, err := client.Login(username, password)

	if err == nil && user != nil {

		sessionData, _ := session.GetStore().Get(r, "session")

		sessionData.Values["user_id"] = int(user["user_id"].(float64))
		sessionData.Values["username"] = user["username"].(string)

		sessionData.Save(r, w)

		session.AddFlash(w, r, "You were logged in")

		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}

	data.Error = err.Error()

	loginTpl.ExecuteTemplate(w, "layout", data)
}

func Register(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {

		registerTpl.ExecuteTemplate(w, "layout", nil)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	data := models.Data{}

	client := NewAPIClient()

	err := client.RegisterUser(username, email, password)

	if err != nil {

		data.Error = err.Error()

		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	session.AddFlash(w, r, "You were successfully registered")

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func FollowUser(w http.ResponseWriter, r *http.Request) {

	user, ok := auth.TryGetUserFromRequest(r)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username := mux.Vars(r)["username"]

	client := NewAPIClient()

	err := client.FollowUser(user.Username, username)

	if err != nil {

		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	session.AddFlash(w, r, "You are now following \""+username+"\"")

	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func UnfollowUser(w http.ResponseWriter, r *http.Request) {

	user, ok := auth.TryGetUserFromRequest(r)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username := mux.Vars(r)["username"]

	client := NewAPIClient()

	err := client.UnfollowUser(user.Username, username)

	if err != nil {

		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	session.AddFlash(w, r, "You are no longer following \""+username+"\"")

	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func Timeline(w http.ResponseWriter, r *http.Request) {

	client := NewAPIClient()

	apiMsgs, err := client.GetPublicMessages()

	if err != nil {

		http.Error(w, err.Error(), http.StatusBadGateway)
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

	err = timelineTpl.ExecuteTemplate(w, "layout", data)

	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func UserTimeline(w http.ResponseWriter, r *http.Request) {

	username := mux.Vars(r)["username"]

	client := NewAPIClient()

	apiMsgs, err := client.GetUserMessages(username)

	if err != nil {

		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	msgs := convertAPIMessagesToTemplateMessages(apiMsgs)

	viewer, logged := auth.TryGetUserFromRequest(r)

	followed := false

	if logged && viewer.Username != username {

		follows, _ := client.GetFollows(viewer.Username)

		for _, f := range follows {

			if f == username {

				followed = true
				break
			}
		}
	}

	data := models.Data{

		FormUsername: username,
		Messages:     msgs,
		Endpoint:     "user_timeline",
		Flashes:      session.GetFlashes(w, r),

		ProfileUser: &models.User{
			Username: username,
		},

		User: &viewer,

		Followed: followed,
	}

	err = timelineTpl.ExecuteTemplate(w, "layout", data)

	if err != nil {

		http.Error(w, err.Error(), 500)
		return
	}
}

func AddMessage(w http.ResponseWriter, r *http.Request) {

	user, ok := auth.TryGetUserFromRequest(r)

	if !ok {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	client := NewAPIClient()

	err := client.PostMessage(user.Username, r.FormValue("text"))

	if err != nil {

		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	session.AddFlash(w, r, "Your message was recorded")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {

	sessionData, _ := session.GetStore().Get(r, "session")

	delete(sessionData.Values, "user_id")
	delete(sessionData.Values, "username")

	sessionData.Save(r, w)

	session.AddFlash(w, r, "You were logged out")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// func MyTimeline(w http.ResponseWriter, r *http.Request) {

// 	user, ok := auth.TryGetUserFromRequest(r)

// 	if !ok {

// 		http.Redirect(
// 			w,
// 			r,
// 			"/public",
// 			http.StatusFound,
// 		)

// 		return
// 	}

// 	client := NewAPIClient()

// 	apiMsgs, err := client.GetUserMessages(user.Username)

// 	if err != nil {

// 		http.Redirect(
// 			w,
// 			r,
// 			"/public",
// 			http.StatusFound,
// 		)

// 		return
// 	}

// 	msgs := convertAPIMessagesToTemplateMessages(apiMsgs)

// 	data := models.Data{

// 		Messages: msgs,

// 		Endpoint: "timeline",

// 		User: &user,

// 		Flashes: session.GetFlashes(w, r),
// 	}

// 	err = timelineTpl.ExecuteTemplate(
// 		w,
// 		"layout",
// 		data,
// 	)

// 	if err != nil {

// 		http.Error(
// 			w,
// 			err.Error(),
// 			http.StatusInternalServerError,
// 		)

// 		return
// 	}
// }

func MyTimeline(w http.ResponseWriter, r *http.Request) {

	user, ok := auth.TryGetUserFromRequest(r)

	if !ok {

		http.Redirect(
			w,
			r,
			"/public",
			http.StatusFound,
		)

		return
	}

	client := NewAPIClient()

	// get your messages
	myMsgs, err := client.GetUserMessages(user.Username)

	if err != nil {

		http.Redirect(w, r, "/public", http.StatusFound)

		return
	}

	allMsgs := myMsgs

	// get users you follow
	follows, err := client.GetFollows(user.Username)

	if err == nil {

		for _, f := range follows {

			msgs, err := client.GetUserMessages(f)

			if err == nil {

				allMsgs = append(allMsgs, msgs...)
			}
		}
	}

	msgs := convertAPIMessagesToTemplateMessages(allMsgs)

	data := models.Data{

		Messages: msgs,

		Endpoint: "timeline",

		User: &user,

		Flashes: session.GetFlashes(w, r),
	}

	err = timelineTpl.ExecuteTemplate(
		w,
		"layout",
		data,
	)

	if err != nil {

		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)

		return
	}
}
