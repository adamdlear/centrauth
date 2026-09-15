package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type LoginService struct {
	logger      *slog.Logger
	users       repository.UserRepository
	credentials repository.CredentialRepository
}

func NewLoginService(logger *slog.Logger, users repository.UserRepository, credentials repository.CredentialRepository) *LoginService {
	return &LoginService{
		logger:      logger,
		users:       users,
		credentials: credentials,
	}
}

func (s *LoginService) VerifyUserWithEmailAndPassword(ctx context.Context, email, password string) (db.User, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return db.User{}, ErrInvalidCredentials
		}
		return db.User{}, err
	}

	cred, err := s.credentials.GetByUserIDAndMethod(ctx, user.ID, "password")
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return db.User{}, ErrInvalidCredentials
		}
		return db.User{}, err
	}

	if cred.PasswordHash == nil {
		return db.User{}, ErrInvalidCredentials
	}

	ok, err := VerifyPassword(password, *cred.PasswordHash)
	if err != nil {
		return db.User{}, err
	}
	if !ok {
		return db.User{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *LoginService) RegisterUser(ctx context.Context, email, password string) (db.User, error) {
	pwdHash, err := HashPassword(password, &DefaultPasswordHashParams)
	if err != nil {
		return db.User{}, fmt.Errorf("hash password: %w", err)
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return db.User{}, fmt.Errorf("generate subject: %w", err)
	}
	sub := base64.RawURLEncoding.EncodeToString(b)

	user := &db.User{
		Subject:   sub,
		Email:     email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	cred := &db.UserCredential{
		Method:       "password",
		PasswordHash: &pwdHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if _, err = s.users.CreateWithCredential(ctx, user, cred); err != nil {
		return db.User{}, fmt.Errorf("create user with credential: %w", err)
	}

	return *user, nil
}
