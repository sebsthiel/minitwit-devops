package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

// configurations
const PORT = "5001"
const DATABASE = "/tmp/minitwit.db"
const PER_PAGE = 30

var database *sql.DB

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

// Data Structs: TODO
type Data struct {
	User         *User
	ProfileUser  *User // Add this
	Error        string
	FormUsername string
	Flashes      []string
	Messages     []map[string]any
	Endpoint     string // Add this
	Followed     bool   // Add this
}

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

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

// TODO right now the password is matched agains exactly what is in the db, should be hash
func Login(w http.ResponseWriter, r *http.Request) {

	// Redirect the user if they are already logged in.
	_, ok := TryGetUserFromRequest(r)
	if ok {
		http.Redirect(w, r, "/public", http.StatusFound)
	}

	// On GET request we return the template.
	if r.Method == http.MethodGet {
		if err := loginTpl.ExecuteTemplate(w, "layout", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	data := Data{
		Error:        "",
		FormUsername: "",
		Flashes:      nil,
		User:         nil,
	}

	// Get username and password from the template form.
	username := r.FormValue("username")
	password := r.FormValue("password")

	userUser := GetUserByUsername(username)

	// Add user to session and redirect
	if userUser != nil && userUser.pw_hash == password {

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
		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}
	// If the username or password is wrong display error in login page.
	data.Error = "Wrong username or password"
	if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func read_sql_schema() string {
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		log.Fatal(err)
	}
	return string(schema)
}

func connect_db() *sql.DB {
	db, err := sql.Open("sqlite3", DATABASE)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func init_db() {
	db := connect_db()
	defer db.Close()
	sqlStmt := read_sql_schema()

	_, err := db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
}

// Queries the database and returns a list of dictionaries.
// USE query_db_one if you only want one result
func query_db(query string, args ...any) ([]map[string]any, error) {
	rows, err := database.Query(query, args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	// results is a slice of rows...
	var results []map[string]any

	for rows.Next() {
		values := make([]any, len(cols))
		valuePtrs := make([]any, len(cols))

		for i := range cols {
			valuePtrs[i] = &values[i]
		}

		// put data into pointers
		err := rows.Scan(valuePtrs...)

		if err != nil {
			return nil, err
		}

		rowMap := make(map[string]any)
		for i, col := range cols {
			rowMap[col] = values[i]
		}

		results = append(results, rowMap)
	}
	return results, nil
}

func query_db_one(query string, args ...any) (map[string]any, error) {
	results, err := query_db(query, args...)
	if err != nil {
		return nil, nil
	}

	if len(results) == 0 {
		return nil, nil
	}

	return results[0], nil
}

func get_user_id(username string) string {
	sqlStmt := fmt.Sprintf("select user_id from user where username = '%s'", username)

	// Query for a single row
	var res, err = query_db_one(sqlStmt)
	if err != nil {
		log.Fatal(err)
		return ""
	}

	if res == nil {
		return ""
	}

	userid := res["user_id"].(int64)
	return strconv.FormatInt(userid, 10)
}

func ensure_schema(db *sql.DB) {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='message'`).Scan(&name)
	if err == sql.ErrNoRows {
		sqlStmt := read_sql_schema()
		if _, err := db.Exec(sqlStmt); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err != nil {
		log.Fatal(err)
	}
}

func FormatDatetime(timestamp int64) string { //return format string
	t := time.Unix(timestamp, 0)
	t = t.UTC()
	result := t.Format("2006-01-02 @ 15:04")
	return result
}

func gravatar_url(email string, size int) string {
	trimmed := strings.ToLower(strings.TrimSpace(email))
	hash := md5.Sum([]byte(trimmed))
	hashString := hex.EncodeToString(hash[:])
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?d=identicon&s=%d", hashString, size)
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
	http.Redirect(w, r, "/user/"+usernameToFollow, http.StatusSeeOther)
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

	http.Redirect(w, r, "/user/"+usernameToUnfollow, http.StatusSeeOther)
}

func AddMessage(w http.ResponseWriter, r *http.Request) {
	user, ok := TryGetUserFromRequest(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	_, err := database.Exec("insert into message (author_id, text, pub_date, flagged)values (?, ?, ?, 0)", user.User_id, r.FormValue("text"), time.Now().Unix())
	if err != nil {
		http.Error(w, "Failed post message: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func UserTimeline(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	msgs, err := query_db(`
        SELECT message.message_id, message.text, message.pub_date, user.username
        FROM message
        JOIN user ON user.user_id = message.author_id
        WHERE user.username = ?
        ORDER BY message.pub_date DESC
        LIMIT ?;
    `, username, PER_PAGE)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// You need to get the profile user data
	profileUserData, err := query_db_one("SELECT user_id, username FROM user WHERE username = ?", username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
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

type User struct {
	User_id  int
	Username string
	Email    string
	pw_hash  string
}

func loadUserFromDB(uid int) User {
	sqlStmt := fmt.Sprintf("select * from user where user_id = %d", uid)

	// Query for a single row
	data, err := query_db_one(sqlStmt)

	if err != nil {
		log.Fatal(err)
	}

	user := User{
		User_id:  int(data["user_id"].(int64)),
		Username: string(data["username"].(string)),
		Email:    string(data["email"].(string)),
		pw_hash:  string(data["pw_hash"].(string)),
	}
	return user

}

func GetUserByUsername(username string) *User {
	// Query database for user
	data, err := query_db_one("SELECT user_id, username, email, pw_hash FROM user WHERE username = ?", username)

	if err != nil {
		log.Fatal("Invalid username")
	}

	if data == nil {
		return nil
	}

	//Store user in User struct
	user := User{
		User_id:  int(data["user_id"].(int64)),
		Username: string(data["username"].(string)),
		Email:    string(data["email"].(string)),
		pw_hash:  string(data["pw_hash"].(string)),
	}

	return &user
}

type contextKey string

const userContextKey = contextKey("user")

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "session")

		if uid, ok := session.Values["user_id"].(int); ok {
			user := loadUserFromDB(uid)

			ctx := context.WithValue(r.Context(), userContextKey, user)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
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
	password := r.FormValue("password")

	if username == "" || password == "" {
		data := Data{Error: "username and password required", FormUsername: username}
		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	_, err := database.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)",
		username, email, password)
	if err != nil {
		data := Data{Error: "Failed to register: " + err.Error(), FormUsername: username}
		registerTpl.ExecuteTemplate(w, "layout", data)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Returns User if exists and boolean. Boolean is true if user exists
func TryGetUserFromRequest(r *http.Request) (User, bool) {
	user, ok := r.Context().Value(userContextKey).(User)
	return user, ok
}

func main() {
	database = connect_db()
	ensure_schema(database)
	fmt.Println("Starting server")
	router := mux.NewRouter()
	router.Use(AuthMiddleware)

	// load stylesheet
	router.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))))

	// Routing handlers
	router.HandleFunc("/", MyTimeline).Methods("GET")

	router.HandleFunc("/public", Timeline).Methods("GET")

	router.HandleFunc("/user/{username}", UserTimeline).Methods("GET")

	router.HandleFunc("/add_message", AddMessage).Methods("POST")

	router.HandleFunc("/login", Login).Methods("GET", "POST")

	router.HandleFunc("/logout", Logout)

	router.HandleFunc("/register", Register).Methods("GET", "POST")

	router.HandleFunc("/{username}/follow", FollowUser).Methods("GET")
	router.HandleFunc("/{username}/unfollow", UnfollowUser).Methods("GET")

	fmt.Println("Started listening on:", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, router))
}
