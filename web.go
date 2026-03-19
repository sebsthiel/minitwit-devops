package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
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
	if whomID == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	follower := Follower{
		Who_id:  user.User_id,
		Whom_id: whomID,
	}

	res := database.Create(&follower)
	if res.Error != nil {
		http.Error(w, "Failed to follow user: "+res.Error.Error(), http.StatusInternalServerError)
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
	if whomID == -1 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	res := database.Where("who_id = ? AND whom_id = ?", user.User_id, whomID).Delete(&Follower{})
	if res.Error != nil {
		http.Error(w, "Failed to unfollow user: "+res.Error.Error(), http.StatusInternalServerError)
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

	var msgs []map[string]any

	res := database.
		Table("message AS m").
		Select("m.*, u.*").
		Joins(`JOIN "user" u ON m.author_id = u.user_id`).
		Where("m.flagged = 0 AND (u.user_id = ? OR u.user_id IN (?) )",
			user.User_id,
			database.Model(&Follower{}).Select("whom_id").Where("who_id = ?", user.User_id),
		).
		Order("m.pub_date DESC").
		Limit(PER_PAGE).
		Find(&msgs)

	if res.Error != nil {
		log.Fatal(res.Error)
	}

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

	var profileUser User

	// You need to get the profile user data
	res = database.
		Select("user_id, username").
		Where("username = ?", username).
		First(&profileUser)

	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}
	if res.Error != nil {
		log.Fatal(res.Error)
	}

	data := Data{
		FormUsername: username,
		ProfileUser:  &profileUser, // Add this
		Messages:     messages,
		Endpoint:     "user_timeline", // Add this
		// You also need to set Followed based on whether the current user follows this user
		Followed: false, // Set this appropriately
		Flashes:  flashes,
	}

	user, ok := TryGetUserFromRequest(r)

	if ok {
		data.User = &user
	}

	var follower Follower

	res = database.
		Select("whom_id").
		Where("who_id = ? AND whom_id = ?", user.User_id, get_user_id(profileUser.Username)).
		First(&follower)

	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// Not following
		} else {
			log.Fatal(res.Error)
		}
	} else {
		data.Followed = true
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func Timeline(w http.ResponseWriter, r *http.Request) {

	var msgs []map[string]any

	res := database.
		Table("message").
		Select(`message.message_id, message.text, message.pub_date, u.username`).
		Joins(`JOIN "user" u ON u.user_id = message.author_id`).
		Order("message.pub_date DESC").
		Limit(PER_PAGE).
		Find(&msgs)

	if res.Error != nil {
		http.Error(w, res.Error.Error(), http.StatusInternalServerError)
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

	user := User{
		Username: username,
		Email:    email,
		Pw_hash:  pwHash,
	}

	res := database.Create(&user)
	if res.Error != nil {
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
