package session

import (
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
)

const sessionName = "session"

var store *sessions.CookieStore

func init() {
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		log.Fatal().Msg("SESSION_KEY not set")
	}
	secureCookies := os.Getenv("COOKIE_SECURE") != "false"

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 30,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}

func GetStore() *sessions.CookieStore {
	return store
}

func GetFlashes(w http.ResponseWriter, r *http.Request) []string {
	sess, _ := store.Get(r, sessionName)

	raw := sess.Flashes()
	if err := sess.Save(r, w); err != nil {
		return nil
	}

	var flashes []string
	for _, f := range raw {
		if msg, ok := f.(string); ok {
			flashes = append(flashes, msg)
		}
	}

	return flashes
}

func AddFlash(w http.ResponseWriter, r *http.Request, msg string) {
	sess, _ := store.Get(r, sessionName)
	sess.AddFlash(msg)
	_ = sess.Save(r, w)
}
