package auth

import (
	"context"
	"net/http"

	"devops/minitwit/internal/models"
	"devops/minitwit/internal/session"
)

type contextKey string

const userContextKey = contextKey("user")

func AuthMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		sess, _ := session.GetStore().Get(r, "session")

		uid, uidOK := sess.Values["user_id"].(int)
		username, usernameOK := sess.Values["username"].(string)

		if uidOK && usernameOK {

			user := models.User{
				User_id:  uid,
				Username: username,
			}

			ctx := context.WithValue(
				r.Context(),
				userContextKey,
				user,
			)

			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

func TryGetUserFromRequest(r *http.Request) (models.User, bool) {

	user, ok := r.Context().Value(userContextKey).(models.User)

	return user, ok
}
