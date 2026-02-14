package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

// configurations
const PORT = "5001"
const DATABASE = "test.db"
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
	template.Must(baseTpl.Clone()).ParseFiles("templates/timeline.html"),
)
var userTimelineTpl = template.Must(
	template.Must(baseTpl.Clone()).ParseFiles("templates/user_timeline.html"),
)

// Data Structs: TODO
type Data struct {
	User         *User
	Error        string
	FormUsername string
	Flashes      []string
	Messages     []map[string]any
}

type User struct {
	Username string
}

var funcMap = template.FuncMap{
	"url": func(urlName string) string {
		return routes[urlName]
	},
}

var routes = map[string]string{
	"timeline":        "/",
	"login":           "/login",
	"public_timeline": "/timeline",
	"logout":          "/logout",
	// TODO: extend with all name -> api route
}

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func ExampleFunction(writer http.ResponseWriter, request *http.Request) {

	data := Data{
		User:         &User{Username: "Test"}, //TODO REMOVE
		Error:        "",
		FormUsername: "",
		Flashes:      nil,
	}
	// templates.ExecuteTemplate(writer, "login.html", data) //TODO remove
	userTimelineTpl.ExecuteTemplate(writer, "example.html", data)
}

// authentication middleware
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "cookie-name")

		if session.Values["authenticated"] != true {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// TODO right now the password is matched agains exactly what is in the db, should be hash
func Login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// if user is already logged in then redirect to timeline
	if session.Values["authenticated"] == true {
		http.Redirect(w, r, "/timeline", http.StatusSeeOther)
		return
	}

	data := Data{
		Error:        "",
		FormUsername: "",
		Flashes:      nil,
	}

	// Get the login page
	if r.Method == http.MethodGet {
		if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// POST login
	if r.Method == http.MethodPost {
		r.ParseForm()

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		data.FormUsername = username

		// Get DB
		db := connect_db()

		var pw string
		query := "SELECT pw_hash FROM user WHERE username = ?"
		err := db.QueryRow(query, username).Scan(&pw)

		// User not found
		if err != nil || pw == "" {
			data.Error = "Invalid username or password"
			loginTpl.ExecuteTemplate(w, "layout", data)
			return
		}

		// Password mismatch
		if pw != password {
			data.Error = "Invalid username or password"
			loginTpl.ExecuteTemplate(w, "layout", data)
			return
		}

		// Set session values (authenticated)
		session.Values["authenticated"] = true
		session.Values["username"] = username
		session.Save(r, w)

		// Redirect after login
		http.Redirect(w, r, "/timeline", http.StatusSeeOther)
		return
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
	db := connect_db()

	sqlStmt := fmt.Sprintf("select user_id from user where username = '%s'", username)

	// Query for a single row
	var res = db.QueryRow(sqlStmt)

	// Var to hold result of scan
	var user_id string

	// The Scan function copies the row entries (Just one entry in this case) to its argument (a pointer)
	var err = res.Scan(&user_id)
	if err != nil {
		log.Fatal(err)
	}

	return user_id
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

// TODO: FormatDatetime(timestamp)
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
	sessionUserID := r.Header.Get("X-User-ID") // placeholder for session logic
	if sessionUserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	usernameToFollow := vars["username"]

	whomID := get_user_id(usernameToFollow)
	if whomID == "" {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, err := database.Exec("INSERT INTO follower (who_id, whom_id) VALUES (?, ?)", sessionUserID, whomID)
	if err != nil {
		http.Error(w, "Failed to follow user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/user/"+usernameToFollow, http.StatusSeeOther)
}

// TODO: UnfollowUser(username)
func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	sessionUserID := r.Header.Get("X-User-ID") // placeholder for session logic
	if sessionUserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	usernameToUnfollow := vars["username"]

	whomID := get_user_id(usernameToUnfollow)
	if whomID == "" {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, err := database.Exec("DELETE FROM follower WHERE who_id = ? AND whom_id = ?", sessionUserID, whomID)
	if err != nil {
		http.Error(w, "Failed to unfollow user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/user/"+usernameToUnfollow, http.StatusSeeOther)
}

// TODO: AddMessage()

func add_message(writer http.ResponseWriter, request *http.Request) {
	session, _ := store.Get(request, "cookie-name")

	// check if user is logged in
	if session.Values["authenticated"] == false {
		//http.Redirect()
	}

	/*
		// get db
		var db = connect_db()

		// make insert stmt
		var stmt = fmt.Sprintf("insert into message (%s, %s, pub_date, flagged)", (session['user_id'], request.form['text'], int(time.time())))

		// if logged in insert message into db
		db.Exec(stmt)
	*/
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// This tells the browser to delete the cookie immediately, effectively destroying the session
	session.Options.MaxAge = -1

	session.Save(r, w)

	http.Redirect(w, r, "/timeline", http.StatusSeeOther)
}

<<<<<<< Updated upstream
func UserTimeline(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
=======
func Register(w http.ResponseWriter, r *http.Request) {
	//var regUserStmt = fmt.Sprintf("select pw_hash from user where username = '%s'", request.Form.Get("username"))
	regUser, err := query_db("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)", r.Form.Get("newusername"), r.Form.Get("newemail"), r.Form.Get("newpassword"))
	if err != nil {
		http.Error(w, "Failed to register user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Registered user: %v\n", regUser)
}

// TODO: Register() done
>>>>>>> Stashed changes

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

	data := Data{
		FormUsername: username,
		Messages:     msgs,
	}

	if err := userTimelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
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
	}

	if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

// TODO: Register() done

type User2 struct {
	user_id  int
	username string
	email    string
	pw_hash  string
}

func loadUserFromDB(uid int) User2 {
	sqlStmt := fmt.Sprintf("select * from user where user_id = %d", uid)

	// Query for a single row
	data, err := query_db_one(sqlStmt)

	if err != nil {
		log.Fatal("Oh nooo")
	}

	user := User2{
		user_id:  int(data["user_id"].(int64)),
		username: string(data["username"].(string)),
		email:    string(data["email"].(string)),
		pw_hash:  string(data["pw_hash"].(string)),
	}
	return user

}

func GetUserByName(username string) User2 {
	// Query database for user
	data, err := query_db_one("SELECT user_id, username, email, pw_hash FROM user WHERE username = ?", username)

	if err != nil {
		log.Fatal("Oh nooo")
	}

	//Store user in User2 struct
	user := User2{
		user_id:  int(data["user_id"].(int64)),
		username: string(data["username"].(string)),
		email:    string(data["email"].(string)),
		pw_hash:  string(data["pw_hash"].(string)),
	}

	return user
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
	// check p
}

func Login2(w http.ResponseWriter, r *http.Request) {

	// Redirect the user if they are already logged in.
	_, ok := r.Context().Value(userContextKey).(User2)
	if ok {
		http.Redirect(w, r, "/public", http.StatusFound)
	}

	data := Data{
		Error:        "",
		FormUsername: "",
		Flashes:      nil,
	}

	// On GET request we return the template.
	if r.Method == http.MethodGet {
		if err := loginTpl.ExecuteTemplate(w, "layout", nil); err != nil { //TODO PASS DATA?
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Get username and password from the template form.
	username := r.FormValue("username")
	password := r.FormValue("password")

	userUser := GetUserByName(username)

	// Add user to session and redirect
	if userUser.pw_hash == password {

		session, err := store.Get(r, "session")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		session.Values["user_id"] = userUser.user_id

		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Could not save session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/public", http.StatusSeeOther)
		return
	}

	data.Error = "Wrong password!!!!!!!!!!!!!!!!!!!"
	// If the username or password is wrong display error in login page.
	if err := loginTpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LoginFormValidation(username string, password string) (bool, error) {
	if username == "" || password == "" {
		//return false, error.New("username or password cannot be empty")
	}
	// credentials look okay
	return true, nil // no error
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
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/public", http.StatusFound)
	}).Methods("GET")

	router.HandleFunc("/public", Timeline).Methods("GET")

	router.HandleFunc("/user/{username}", UserTimeline).Methods("GET")

	router.HandleFunc("/login", Login2).Methods("GET", "POST")

	router.HandleFunc("/logout", Logout)

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerTpl.ExecuteTemplate(w, "layout", nil)
	}).Methods("GET")

	fmt.Println("Started listining on:", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, router))
}
