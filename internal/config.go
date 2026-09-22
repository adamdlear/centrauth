package internal

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/session"
)

type ServerConfig struct {
	Addr         string
	IssuerURL    string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type AppConfig struct {
	ServerConfig          ServerConfig
	DBConfig              db.DBConfig
	SessionConfig         session.Config
	OperatorSessionConfig session.Config
	RegistrationEnabled   bool
}

func LoadConfig() (AppConfig, error) {
	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = ":8080"
	}

	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "http://localhost:8080"
	}

	parsedIssuer, err := url.Parse(issuerURL)
	if err != nil {
		return AppConfig{}, fmt.Errorf("invalid ISSUER_URL: %w", err)
	}

	cookieName := os.Getenv("SESSION_COOKIE_NAME")
	if cookieName == "" {
		cookieName = "centrauth_session"
	}

	sessionTTL := 24 * time.Hour
	if raw := os.Getenv("SESSION_TTL"); raw != "" {
		sessionTTL, err = time.ParseDuration(raw)
		if err != nil {
			return AppConfig{}, fmt.Errorf("invalid SESSION_TTL: %w", err)
		}
	}

	operatorCookieName := os.Getenv("OPERATOR_SESSION_COOKIE_NAME")
	if operatorCookieName == "" {
		operatorCookieName = "centrauth_operator"
	}

	operatorSessionTTL := sessionTTL
	if raw := os.Getenv("OPERATOR_SESSION_TTL"); raw != "" {
		operatorSessionTTL, err = time.ParseDuration(raw)
		if err != nil {
			return AppConfig{}, fmt.Errorf("invalid OPERATOR_SESSION_TTL: %w", err)
		}
	}

	dbPort, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		return AppConfig{}, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	registrationEnabled := os.Getenv("ENABLE_REGISTRATION") == "true"

	return AppConfig{
		ServerConfig: ServerConfig{
			Addr:         serverAddr,
			IssuerURL:    issuerURL,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		DBConfig: db.DBConfig{
			Host:     os.Getenv("DB_HOST"),
			User:     os.Getenv("DB_USERNAME"),
			Password: os.Getenv("DB_PASSWORD"),
			DBName:   os.Getenv("DB_DATABASE"),
			Port:     dbPort,
		},
		SessionConfig: session.Config{
			CookieName: cookieName,
			TTL:        sessionTTL,
			Secure:     parsedIssuer.Scheme == "https",
		},
		OperatorSessionConfig: session.Config{
			CookieName: operatorCookieName,
			TTL:        operatorSessionTTL,
			Secure:     parsedIssuer.Scheme == "https",
		},
		RegistrationEnabled: registrationEnabled,
	}, nil
}
