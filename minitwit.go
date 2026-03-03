package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

type User struct {
	User_id  int
	Username string
	Email    string
	pw_hash  string
}

type Message struct {
	Message_id int
	Author_id  int
	Text       string
	Pub_date   int
	Flagged    int
}

type Follower struct {
	Who_id  int
	Whom_id int
}

// configurations
const PORT = "5001"
const DATABASE = "/tmp/minitwit.db"
const PER_PAGE = 30

var database *gorm.DB

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

type contextKey string

const userContextKey = contextKey("user")

func read_sql_schema() string {
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		log.Fatal(err)
	}
	return string(schema)
}

func connect_db() *gorm.DB {
	db, err := gorm.Open(sqlite.Open(DATABASE), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&User{}, &Message{}, &Follower{})
	return db
}

func get_user_id(username string) string {
	var user User
	res := database.First(&user, "username = ?", username)
	if res.Error != nil {
		log.Fatal(res.Error)
	}
	return string(user.User_id)
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
	AddFlash(w, r, "Your message was recorded")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetFlashes(w http.ResponseWriter, r *http.Request) []string {
	session, _ := store.Get(r, "session")

	// Get the raw []interface{} values from the session
	raw := session.Flashes()
	if err := session.Save(r, w); err != nil {
		return nil // or we could handle error properly
	}

	// Extract the messages
	var flashes []string
	for _, f := range raw {
		if msg, ok := f.(string); ok {
			flashes = append(flashes, msg)
		}
	}

	return flashes
}

func AddFlash(w http.ResponseWriter, r *http.Request, msg string) {
	session, _ := store.Get(r, "session")
	session.AddFlash(msg)
	session.Save(r, w)
}

func loadUserFromDB(uid int) (User, bool) {
	var user User
	res := database.First(&user, "user_id = ?", uid)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return User{}, false
		} else {
			log.Fatal(res.Error)
		}
	}
	return user, true
}

func GetUserByUsername(username string) *User {
	var user User
	res := database.First(&user, "username = ?", username)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil
		} else {
			log.Fatal("Invalid username")
		}
	}
	return &user
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "session")

		if uid, ok := session.Values["user_id"].(int); ok {
			user, ok := loadUserFromDB(uid)
			if ok {
				ctx := context.WithValue(r.Context(), userContextKey, user)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ValidateRegister(username string, email string, firstPassword string, secondPassword string) (bool, string) {
	errormessage := ""

	// Have to enter a username
	if username == "" {
		return false, "You have to enter a username"
	}

	if firstPassword == "" {
		return false, "You have to enter a password"
	}

	if firstPassword != secondPassword {
		return false, "The two passwords do not match"
	}

	_, mailErr := mail.ParseAddress(email)
	if mailErr != nil {
		return false, "You have to enter a valid email address"
	}

	userExists, _ := query_db_one("SELECT username FROM user WHERE username = ?", username)

	// User already exists
	if userExists["username"] != nil {
		return false, "The username is already taken"
	}

	return true, errormessage
}

func ValidateLogin(username string, password string) (*User, string) {
	existingUser := GetUserByUsername(username)

	if existingUser == nil {
		return nil, "Invalid username"
	}

	if !CheckPasswordHash(password, existingUser.pw_hash) {
		return nil, "Invalid password"
	}

	return existingUser, ""
}

// Returns User if exists and boolean. Boolean is true if user exists
func TryGetUserFromRequest(r *http.Request) (User, bool) {
	user, ok := r.Context().Value(userContextKey).(User)
	return user, ok
}

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 30,
		HttpOnly: true,

		// IMPORTANT for pytest/local:
		Secure:   false,
		SameSite: http.SameSiteLaxMode, // or DefaultMode
	}
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
	RegisterAPIRoutes(router) /* This i believe has be happen before the normal routes
	due to the username route which actually could match a username "api"*/
	RegisterRoutes(router)

	fmt.Println("Started listening on:", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, router))
}
