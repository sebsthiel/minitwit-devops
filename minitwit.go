package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

// configuration
const PORT = "5001"
const DATABASE = "/tmp/minitwit.db"

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
	"timeline": "/",
	"login":    "/login",
	// TODO: extend with all name -> api route
}

func read_sql_schema() string {
	schema, err := os.ReadFile("python_implementation/schema.sql")
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
func query_db(query string, args any) ([]map[string]any, error) {
	rows, err := database.Query(query, args)
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

func query_db_one(query string, args any) (map[string]any, error) {
	results, err := query_db(query, args)
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
		LIMIT 30;
	`, nil)
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

}).Methods("GET")





	router.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logout (placeholder)\n"))
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
		LIMIT 30;
	`, username)
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
