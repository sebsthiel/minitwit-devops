package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/gorilla/mux"
)

const PORT = "5000"

// Data Structs: TODO

var templates = template.Must(template.ParseGlob("templates/*.html"))

func ExampleFunction(writer http.ResponseWriter, request *http.Request) {

	templates.ExecuteTemplate(writer, "example.html", nil)
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

// TODO this function should probably return a string
func get_user_id(username string) sql.Result {
	db := connect_db()

	sqlStmt := fmt.Sprintf("select user_id from user where username = %s", username)

	var id, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	return id
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

// TODO: Login() done 

// TODO: Logout() done

// TODO: Register() done 

func main() {
	fmt.Println("Starting server")
	router := mux.NewRouter()

	// load stylesheet
	router.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))))

	router.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Public timeline (placeholder)\n"))
	}).Methods("GET")

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
    		w.WriteHeader(http.StatusOK)
    		w.Write([]byte("Login page (placeholder)\n"))
	}).Methods("GET")

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
