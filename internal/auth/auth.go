package auth

import (
	"context"
	"net/http"

	"devops/minitwit/internal/models"
	"devops/minitwit/internal/session"

	"gorm.io/gorm"
)

type contextKey string

const userContextKey = contextKey("user")

var database *gorm.DB

func SetDB(db *gorm.DB) {
	database = db
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionData, _ := session.GetStore().Get(r, "session")

		if uid, ok := sessionData.Values["user_id"].(int); ok {
			var user models.User
			res := database.First(&user, "user_id = ?", uid)
			if res.Error == nil {
				ctx := context.WithValue(r.Context(), userContextKey, user)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func TryGetUserFromRequest(r *http.Request) (models.User, bool) {
	user, ok := r.Context().Value(userContextKey).(models.User)
	return user, ok
}