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

// TODO: Timeline()

// TODO: UserTimeline(username)

// TODO: FollowUser(username)

// TODO: UnfollowUser(username)

// TODO: AddMessage()

// TODO: Login()

// TODO: Logout()

// TODO: Register()

func main() {
	fmt.Println("Starting server")
	router := mux.NewRouter()

	// load stylesheet
	router.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static"))))

	router.HandleFunc("/", ExampleFunction).Methods(("GET"))
	// TODO: add routes here

	fmt.Println("Started listining on:", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, router))
}
