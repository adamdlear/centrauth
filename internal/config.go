package internal

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
)

type ServerConfig struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type AppConfig struct {
	ServerConfig ServerConfig
	DBConfig     db.DBConfig
}

func LoadConfig() (AppConfig, error) {
	port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		return AppConfig{}, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	return AppConfig{
		ServerConfig: ServerConfig{
			Addr:         ":8080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		DBConfig: db.DBConfig{
			Host:     os.Getenv("DB_HOST"),
			User:     os.Getenv("DB_USERNAME"),
			Password: os.Getenv("DB_PASSWORD"),
			DBName:   os.Getenv("DB_DATABASE"),
			Port:     port,
		},
	}, nil
}
