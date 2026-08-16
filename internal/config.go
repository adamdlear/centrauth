package internal

import (
	"time"
)

type ServerConfig struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type AppConfig struct {
	ServerConfig ServerConfig
}

func LoadConfig() (AppConfig, error) {
	return AppConfig{
		ServerConfig: ServerConfig{
			Addr:         ":8080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}, nil
}
