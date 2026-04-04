package db

import (
	stdlog "log"
	"os"

	"devops/minitwit/internal/models"

	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

const defaultSQLitePath = "minitwit.db"

func Connect() *gorm.DB {
	var dialector gorm.Dialector

	dbURL := os.Getenv("DATABASE_PATH")
	if dbURL != "" {
		dialector = postgres.Open(dbURL)
	} else {
		dialector = sqlite.Open(defaultSQLitePath)
	}

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
		log.Fatal().Stack().Err(err).Msg("GORM error when opening database")
	}

	db.AutoMigrate(&models.User{}, &models.Message{}, &models.Follower{})
	return db
}
