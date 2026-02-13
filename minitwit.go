package main

import (
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

// configurationf
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

func Login(writer http.ResponseWriter, request *http.Request) {
	session, _ := store.Get(request, "cookie-name")

	data := Data{
		User:         &User{Username: "Test"}, //TODO REMOVE
		Error:        "",
		FormUsername: "",
		Flashes:      nil,
	}

	// TODO
	// if user is already loggen in then redirect to timeline
	if session.Values["authenticated"] == true {
		// Redirect
	}

	// get db
	db := connect_db()

	// must be called to populate the form
	request.ParseForm()
	var pw string

	// check if username is in db
	var usernameStmt = fmt.Sprintf("select pw_hash from user where username = '%s'", request.Form.Get("username"))
	db.QueryRow(usernameStmt).Scan(&pw)

	// if user in not in db, or pw is incorrect set error message, else login
	if pw == "" {
		fmt.Print("ski")
		data.Error = "Invalid username"
	} else if pw != request.Form.Get("password") {
		data.Error = "Invalid password"
	} else { // Set user as authenticated
		fmt.Print("logged in") // TODO remove once convinced
		session.Values["authenticated"] = true
		session.Save(request, writer)
	}

	// Authentication goes here
	// ...

	if err := loginTpl.ExecuteTemplate(writer, "layout", data); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
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

	fmt.Print("logged out") // TODO remove once convinced
	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

// TODO: Register() done

func main() {
	database = connect_db()
	ensure_schema(database)
	fmt.Println("Starting server")
	router := mux.NewRouter()

	// load stylesheet
	router.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))))

	router.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {

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
		fmt.Printf("%#v\n", msgs[0])

		if err := timelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	}).Methods("GET")

	router.HandleFunc("/public", ExampleFunction)
	/*
		router.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Public timeline (placeholder)\n"))
		}).Methods("GET")
	*/
	router.HandleFunc("/login", Login)

	/*
		router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Login page (placeholder)\n"))
		}).Methods("GET")*/

	router.HandleFunc("/logout", Logout)

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := loginTpl.ExecuteTemplate(w, "layout", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerTpl.ExecuteTemplate(w, "layout", nil)
	}).Methods("GET")

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/public", http.StatusFound)
	}).Methods("GET")

	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
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

		data := Data{
			FormUsername: username,
			Messages:     msgs,
		}

		if err := userTimelineTpl.ExecuteTemplate(w, "layout", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")

	fmt.Println("Started listining on:", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, router))
}
