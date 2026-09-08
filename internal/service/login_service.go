package service

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type LoginService struct {
	users       repository.UserRepository
	credentials repository.CredentialRepository
}

func NewLoginService(users repository.UserRepository, credentials repository.CredentialRepository) *LoginService {
	return &LoginService{users: users, credentials: credentials}
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
