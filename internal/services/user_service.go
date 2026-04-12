package services

import (
	"errors"
	"net/mail"

	"devops/minitwit/internal/models"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	queryUsername = "username = ?"
	queryUserID   = "user_id = ?"
)

var database *gorm.DB

func SetDB(db *gorm.DB) {
	database = db
}

func GetUserID(username string) int {
	var user models.User
	res := database.First(&user, queryUsername, username)
	if res.Error != nil {
		log.Warn().Err(res.Error).Str("username", username).Msg("Failed to get user ID")
		return -1
	}
	return user.User_id
}

func LoadUserFromDB(uid int) (models.User, bool) {
	var user models.User
	res := database.First(&user, queryUserID, uid)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return models.User{}, false
		}
		log.Warn().Stack().Err(res.Error).Msg("")
		return models.User{}, false
	}
	return user, true
}

func GetUserByUsername(username string) *models.User {
	var user models.User
	res := database.First(&user, queryUsername, username)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil
		}
		log.Warn().Err(res.Error).Msg("Invalid username")
		return nil
	}
	return &user
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ValidateRegister(username, email, firstPassword, secondPassword string) (bool, string) {
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

	var user models.User
	res := database.First(&user, queryUsername, username)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return true, ""
		}
		return false, res.Error.Error()
	}

	return false, "The username is already taken"
}

func ValidateLogin(username, password string) (*models.User, string) {
	existingUser := GetUserByUsername(username)

	if existingUser == nil {
		return nil, "Invalid username"
	}

	if !CheckPasswordHash(password, existingUser.Pw_hash) {
		return nil, "Invalid password"
	}

	return existingUser, ""
}
