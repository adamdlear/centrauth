package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/repository"
)

type OperatorLoginService struct {
	logger    *slog.Logger
	operators repository.OperatorRepository

	dummyOnce sync.Once
	dummyHash string
}

func NewOperatorLoginService(logger *slog.Logger, operators repository.OperatorRepository) *OperatorLoginService {
	return &OperatorLoginService{
		logger:    logger,
		operators: operators,
	}
}

func (s *OperatorLoginService) VerifyOperatorWithEmailAndPassword(ctx context.Context, email, password string) (db.Operator, error) {
	operator, err := s.operators.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			s.verifyDummy(password)
			return db.Operator{}, ErrInvalidCredentials
		}
		return db.Operator{}, err
	}

	ok, err := VerifyPassword(password, operator.PasswordHash)
	if err != nil {
		return db.Operator{}, err
	}
	if !ok {
		return db.Operator{}, ErrInvalidCredentials
	}

	return operator, nil
}

func (s *OperatorLoginService) verifyDummy(password string) {
	s.dummyOnce.Do(func() {
		hash, err := HashPassword(password, &DefaultPasswordHashParams)
		if err != nil {
			s.logger.Error("failed to generate dummy password hash", "error", err)
			return
		}
		s.dummyHash = hash
	})
	if s.dummyHash == "" {
		return
	}
	_, _ = VerifyPassword(password, s.dummyHash)
}
