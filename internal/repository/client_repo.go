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
	Update(ctx context.Context, client *db.OAuthClient) (db.OAuthClient, error)
	List(ctx context.Context) ([]db.OAuthClient, error)
	ListByEnvironment(ctx context.Context, environment string) ([]db.OAuthClient, error)
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

func (r *gormClientRepo) Update(ctx context.Context, client *db.OAuthClient) (db.OAuthClient, error) {
	rows, err := gorm.G[db.OAuthClient](r.db).
		Where("id = ?", client.ID).
		Select("*").
		Omit("id").
		Updates(ctx, *client)
	if err != nil {
		return *client, err
	}
	if rows == 0 {
		return *client, ErrNotFound
	}
	return *client, nil
}

func (r *gormClientRepo) List(ctx context.Context) ([]db.OAuthClient, error) {
	return gorm.G[db.OAuthClient](r.db).Find(ctx)
}

func (r *gormClientRepo) ListByEnvironment(ctx context.Context, environment string) ([]db.OAuthClient, error) {
	return gorm.G[db.OAuthClient](r.db).Where("environment = ?", environment).Find(ctx)
}
