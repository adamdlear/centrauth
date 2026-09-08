package repository

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type CredentialRepository interface {
	GetByUserIDAndMethod(ctx context.Context, userID int64, method string) (db.UserCredential, error)
	Create(ctx context.Context, cred *db.UserCredential) (db.UserCredential, error)
}

type gormCredentialRepo struct {
	db *gorm.DB
}

func NewGormCredentialRepo(db *gorm.DB) CredentialRepository {
	return &gormCredentialRepo{db: db}
}

func (r *gormCredentialRepo) GetByUserIDAndMethod(ctx context.Context, userID int64, method string) (db.UserCredential, error) {
	cred, err := gorm.G[db.UserCredential](r.db).
		Where("user_id = ?", userID).
		Where("method = ?", method).
		First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return cred, ErrNotFound
	}
	return cred, err
}

func (r *gormCredentialRepo) Create(ctx context.Context, cred *db.UserCredential) (db.UserCredential, error) {
	err := gorm.G[db.UserCredential](r.db).Create(ctx, cred)
	return *cred, err
}
