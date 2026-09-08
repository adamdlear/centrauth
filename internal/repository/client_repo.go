package repository

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (db.OAuthClient, error)
	Create(ctx context.Context, client *db.OAuthClient) (db.OAuthClient, error)
}

type gormClientRepo struct {
	db *gorm.DB
}

func NewGormClientRepo(db *gorm.DB) ClientRepository {
	return &gormClientRepo{db: db}
}

func (r *gormClientRepo) GetByClientID(ctx context.Context, clientID string) (db.OAuthClient, error) {
	client, err := gorm.G[db.OAuthClient](r.db).Where("client_id = ?", clientID).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return client, ErrNotFound
	}
	return client, err
}

func (r *gormClientRepo) Create(ctx context.Context, client *db.OAuthClient) (db.OAuthClient, error) {
	err := gorm.G[db.OAuthClient](r.db).Create(ctx, client)
	return *client, err
}
