package minitwit

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"

	"golang.org/x/crypto/bcrypt"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	User_id  int `gorm:"column:user_id;primaryKey;autoIncrement"`
	Username string
	Email    string
	Pw_hash  string `gorm:"column:pw_hash"`
}

type Message struct {
	Message_id int `gorm:"column:message_id;primaryKey;autoIncrement"`
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
const DATABASE_DEFAULT = "/tmp/minitwit.db"
const PER_PAGE = 30

var database *gorm.DB

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

type contextKey string

const userContextKey = contextKey("user")

func Connect_db() *gorm.DB {
	var dialector gorm.Dialector
	if p := os.Getenv("DATABASE_PATH"); p != "" {
		dialector = postgres.Open(p)
	} else {
		dialector = sqlite.Open(DATABASE_DEFAULT)
	}

	// Costumize logger //TODO USE zerolog?
	loggergorm := gormlogger.New(
		stdlog.New(os.Stdout, "\r\n", stdlog.LstdFlags),
		gormlogger.Config{
			LogLevel:                  gormlogger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	db, err := gorm.Open(dialector, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		Logger: loggergorm,
	})
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("GORM error when open database")
	}
	db.AutoMigrate(&User{}, &Message{}, &Follower{})
	return db
}

func get_user_id(username string) int {
	var user User
	res := database.First(&user, "username = ?", username)
	if res.Error != nil {
		return -1
	}
	return user.User_id
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

	res := database.Create(&Message{Author_id: user.User_id, Text: r.FormValue("text"), Pub_date: int(time.Now().Unix())})
	if res.Error != nil {
		http.Error(w, "Failed post message: "+res.Error.Error(), http.StatusInternalServerError)
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
			log.Warn().Stack().Err(res.Error).Msg("")
			return User{}, false
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
			log.Warn().Err(res.Error).Msg("Invalid username")
			return nil
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

func CheckPasswordHash(password string, hash string) bool {
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

	var user User
	res := database.First(&user, "username = ?", username)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return true, errormessage
		} else {
			return false, res.Error.Error()
		}
	}

	return false, "The username is already taken"
}

func ValidateLogin(username string, password string) (*User, string) {
	existingUser := GetUserByUsername(username)

	if existingUser == nil {
		return nil, "Invalid username"
	}

	if !CheckPasswordHash(password, existingUser.Pw_hash) {
		print(" ID: ", existingUser.User_id)
		print(" UN: ", existingUser.Username)
		print(" Email: ", existingUser.Email)
		print(" HASH: ", existingUser.Pw_hash)
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

func loggingConfig() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// If environment variable is not set then it will disable logging
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {

		switch logLevel {
		case "debug":
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		case "info":
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		case "warn":
			zerolog.SetGlobalLevel(zerolog.WarnLevel)
		case "error":
			zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		case "fatal":
			zerolog.SetGlobalLevel(zerolog.FatalLevel)
		default:
			zerolog.SetGlobalLevel(zerolog.Disabled)
		}

	} else {
		zerolog.SetGlobalLevel(zerolog.Disabled)
	}
}

func StartLogging() {
	loggingConfig()
	log.Info().Msg("Starting server")
}