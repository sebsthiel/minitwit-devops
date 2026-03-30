package session

import (
	"net/http"

	"github.com/gorilla/sessions"
)

var (
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 30,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

func GetStore() *sessions.CookieStore {
	return store
}

func GetFlashes(w http.ResponseWriter, r *http.Request) []string {
	session, _ := store.Get(r, "session")

	raw := session.Flashes()
	if err := session.Save(r, w); err != nil {
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
	session, _ := store.Get(r, "session")
	session.AddFlash(msg)
	session.Save(r, w)
}