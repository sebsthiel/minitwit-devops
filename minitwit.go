package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

const PORT = "5000"

// Data Structs: TODO
type Data struct {
	User         *User
	Error        string
	FormUsername string
	Flashes      []string
}

type User struct {
	Username string
}

var funcMap = template.FuncMap{
	"url": func(urlName string) string {
		return routes[urlName]
	},
}

var templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))

var routes = map[string]string{
	"timeline": "/",
	"login":    "/login",
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
	templates.ExecuteTemplate(writer, "example.html", data)
}

func read_sql_schema() string {
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		log.Fatal(err)
	}
	return string(schema)
}

func connect_db() *sql.DB {
	db, err := sql.Open("sqlite3", "/tmp/minitwit.db")
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

func query_db() {

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

// TODO: QueryDb()

// TODO: FormatDatetime(timestamp)

// TODO: GravatarUrl(email, size=80)

// TODO: BeforeRequest()

// TODO: Timeline()  done

// TODO: UserTimeline(username) done

// TODO: FollowUser(username)

// TODO: UnfollowUser(username)

// TODO: AddMessage()

func add_message() {
	// check if user is logged in

	/*
		// get db
		var db = connect_db()

		// make insert stmt
		var stmt = fmt.Sprintf("insert into message (%s, %s, pub_date, flagged)", (session['user_id'], request.form['text'], int(time.time())))

		// if logged in insert message into db
		db.Exec(stmt)
	*/
}

// TODO: Login() done

func login(w http.ResponseWriter, r *http.Request) {
	// if user is already loggen in then redirect to timeline

	// get db
	// var db = connect_db()

	// check if username is in db

	// check if password matches

	session, _ := store.Get(r, "cookie-name")
	// Authentication goes here
	// ...

	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Save(r, w)
}

// TODO: Logout() done

func logout(w http.ResponseWriter, r *http.Request) {

	session, _ := store.Get(r, "cookie-name")

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

// TODO: Register() done

func main() {

	fmt.Println("Starting server")
	router := mux.NewRouter()

	// load stylesheet
	router.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))))

	router.HandleFunc("/public", ExampleFunction)
	/*
		router.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Public timeline (placeholder)\n"))
		}).Methods("GET")
	*/
	router.HandleFunc("/login", login)

	/*
		router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Login page (placeholder)\n"))
		}).Methods("GET")*/

	router.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logout (placeholder)\n"))
	}).Methods("GET")

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Register (placeholder)\n"))
	}).Methods("GET")

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Timeline (placeholder)\n"))
	}).Methods("GET")

	router.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User timeline for " + username + " (placeholder)\n"))
	}).Methods("GET")

	fmt.Println("Started listining on:", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, router))
}
