package main

import (
	"html/template"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

var baseTpl = template.Must(
	template.New("base").Funcs(funcMap).ParseFiles("templates/layout.html"),
)

var loginTpl = template.Must(
	template.Must(baseTpl.Clone()).ParseFiles("templates/login.html"),
)

var registerTpl = template.Must(
	template.Must(baseTpl.Clone()).ParseFiles("templates/register.html"),
)
var timelineTpl = template.Must(
	template.Must(baseTpl.Clone()).Funcs(funcMap).ParseFiles("templates/timeline.html"),
)
var userTimelineTpl = template.Must(
	template.Must(baseTpl.Clone()).ParseFiles("templates/user_timeline.html"),
)

var funcMap = template.FuncMap{
	"url": func(urlName string) string {
		return routes[urlName]
	},
	"gravatar": gravatar_url,
	"datetime": func(ts any) string {
		switch v := ts.(type) {
		case int64:
			return FormatDatetime(v)
		case int:
			return FormatDatetime(int64(v))
		default:
			return ""
		}
	},
}

var routes = map[string]string{
	"timeline":        "/",
	"login":           "/login",
	"public_timeline": "/public",
	"register":        "/register",
	"logout":          "/logout",
	// TODO: extend with all name -> api route
}

// TODO right now the password is matched agains exactly what is in the db, should be hash
func Login(w http.ResponseWriter, r *http.Request) {

	// Redirect the user if they are already logged in.
	_, ok := TryGetUserFromRequest(r)
	if ok {
		http.Redirect(w, r, "/public", http.StatusFound)
	}

	data := Data{
		Error:        "",
		FormUsername: "",
		Flashes:      GetFlashes(w, r),
		User:         nil,
	}

	// On GET request we return the template.
	if r.Method == http.MethodGet {
		if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Get username and password from the template form.
	username := r.FormValue("username")
	password := r.FormValue("password")

	userUser, errorMessage := ValidateLogin(username, password)

	// Add user to session and redirect
	if userUser != nil {

		session, err := store.Get(r, "session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		session.Values["user_id"] = userUser.User_id

		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Could not save session", http.StatusInternalServerError)
			return
		}
		AddFlash(w, r, "You were logged in")
		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}
	// If the username or password is wrong display error in login page.
	data.Error = errorMessage
	if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// TODO: FollowUser(username)
func FollowUser(w http.ResponseWriter, r *http.Request) {
	user, ok := TryGetUserFromRequest(r)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		//http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	vars := mux.Vars(r)
	usernameToFollow := vars["username"]

	whomID := get_user_id(usernameToFollow)
	if whomID == "" {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, err := database.Exec("INSERT INTO follower (who_id, whom_id) VALUES (?, ?)", user.User_id, whomID)
	if err != nil {
		http.Error(w, "Failed to follow user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Add the flash message to the session:
	AddFlash(w, r, "You are now following \""+usernameToFollow+"\"")
	http.Redirect(w, r, "/"+usernameToFollow, http.StatusSeeOther)
}

// TODO: UnfollowUser(username)
func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	user, ok := TryGetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		//http.Redirect(w, r, "/public", http.StatusFound)
		return
	}
	vars := mux.Vars(r)
	usernameToUnfollow := vars["username"]

	whomID := get_user_id(usernameToUnfollow)
	if whomID == "" {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, err := database.Exec("DELETE FROM follower WHERE who_id = ? AND whom_id = ?", user.User_id, whomID)
	if err != nil {
		http.Error(w, "Failed to unfollow user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	AddFlash(w, r, "You are no longer following \""+usernameToUnfollow+"\"")
	http.Redirect(w, r, "/"+usernameToUnfollow, http.StatusSeeOther)
}

// Removes user_id from session and redirects to "/"
func Logout(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	delete(session.Values, "user_id")

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "could not save session", http.StatusInternalServerError)
		return
	}
	AddFlash(w, r, "You were logged out")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func MyTimeline(w http.ResponseWriter, r *http.Request) {
	user, ok := TryGetUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	msgs, _ := query_db(`
        select message.*, user.* from message, user
        where message.flagged = 0 and message.author_id = user.user_id and (
            user.user_id = ? or
            user.user_id in (select whom_id from follower
                                    where who_id = ?))
        order by message.pub_date desc limit ?
    `, user.User_id, user.User_id, PER_PAGE)

	data := Data{
		Messages: msgs,
		Endpoint: "timeline", // Add this line
		User:     &user,
		Flashes:  GetFlashes(w, r),
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func UserTimeline(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	flashes := GetFlashes(w, r)

	msgs, err := query_db(`
        SELECT message.message_id, message.text, message.pub_date, user.username
        FROM message
        JOIN user ON user.user_id = message.author_id
        WHERE user.username = ?
        ORDER BY message.pub_date DESC
        LIMIT ?;
    `, username, PER_PAGE)
	if err != nil {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	// You need to get the profile user data
	profileUserData, err := query_db_one("SELECT user_id, username FROM user WHERE username = ?", username)
	if err != nil || profileUserData["user_id"] == nil {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	profileUserName := profileUserData["username"].(string)

	profileUserId, err := strconv.Atoi(get_user_id(profileUserName))

	// Create ProfileUser
	profileUser := &User{
		Username: profileUserName,
		User_id:  profileUserId,
	}

	data := Data{
		FormUsername: username,
		ProfileUser:  profileUser, // Add this
		Messages:     msgs,
		Endpoint:     "user_timeline", // Add this
		// You also need to set Followed based on whether the current user follows this user
		Followed: false, // Set this appropriately
		Flashes:  flashes,
	}

	user, ok := TryGetUserFromRequest(r)

	if ok {
		data.User = &user
	}

	whom_id_data, err := query_db_one("select whom_id from follower where who_id = ? AND whom_id = ?", user.User_id, profileUserId)

	if whom_id_data["whom_id"] != nil {
		data.Followed = true
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func Timeline(w http.ResponseWriter, r *http.Request) {

	msgs, err := query_db(`
		SELECT message.message_id, message.text, message.pub_date, user.username
		FROM message
		JOIN user ON user.user_id = message.author_id
		ORDER BY message.pub_date DESC
		LIMIT ?;
	`, PER_PAGE)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := Data{
		Messages: msgs,
		Endpoint: "public_timeline", // Add this line
		Flashes:  GetFlashes(w, r),
	}
	user, ok := TryGetUserFromRequest(r)

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

	data := Data{}

	ok, registerError := ValidateRegister(username, email, firstPassword, secondPassword)

	data.Error = registerError
	if !ok {
		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	var pwHash, err = HashPassword(firstPassword)

	_, err = database.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)",
		username, email, pwHash)
	if err != nil {
		data = Data{Error: "Failed to register: " + err.Error(), FormUsername: username}
		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}
	AddFlash(w, r, "You were successfully registered and can login now")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

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
