package web

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html/template"
	"strings"
	"time"
)

var funcMap = template.FuncMap{
	"url": func(urlName string) string {
		return routes[urlName]
	},
	"gravatar": gravatarURL,
	"datetime": func(ts any) string {
		switch v := ts.(type) {
		case int64:
			return FormatDatetime(v)
		case int:
			return FormatDatetime(int64(v))
		default:
			return ""
		}
	},
}

var routes = map[string]string{
	"timeline":        "/",
	"login":           "/login",
	"public_timeline": "/public",
	"register":        "/register",
	"logout":          "/logout",
}

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
	template.Must(baseTpl.Clone()).Funcs(funcMap).ParseFiles("templates/timeline.html"),
)

func FormatDatetime(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	t = t.UTC()
	return t.Format("2006-01-02 @ 15:04")
}

func gravatarURL(email string, size int) string {
	trimmed := strings.ToLower(strings.TrimSpace(email))
	// Gravatar requires MD5 of the normalized email address for avatar lookup.
	hash := md5.Sum([]byte(trimmed))
	hashString := hex.EncodeToString(hash[:])
	return fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=identicon&s=%d", hashString, size)
}
