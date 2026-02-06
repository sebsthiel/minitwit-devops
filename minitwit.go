package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/gorilla/mux"
)

const PORT = "5000"

// Data Structs: TODO

var templates = template.Must(template.ParseGlob("templates/*.html"))

func ExampleFunction(writer http.ResponseWriter, request *http.Request) {

	templates.ExecuteTemplate(writer, "example.html", nil)
}

// TODO: ConnectDb()

// TODO: InitDb()

// TODO: QueryDb()

// TODO: GetUser_id(username)

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
