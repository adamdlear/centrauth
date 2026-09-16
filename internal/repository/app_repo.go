package repository

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type ApplicationRepository interface {
	Create(ctx context.Context, app *db.Application) (db.Application, error)
	GetByID(ctx context.Context, id int64) (db.Application, error)
	List(ctx context.Context) ([]db.Application, error)
	Update(ctx context.Context, app *db.Application) (db.Application, error)
	GetWithClients(ctx context.Context, id int64) (db.Application, []db.OAuthClient, error)
}

type gormApplicationRepo struct {
	db *gorm.DB
}

func NewGormApplicationRepo(db *gorm.DB) ApplicationRepository {
	return &gormApplicationRepo{db: db}
}

func (r *gormApplicationRepo) Create(ctx context.Context, app *db.Application) (db.Application, error) {
	err := gorm.G[db.Application](r.db).Create(ctx, app)
	return *app, err
}

func (r *gormApplicationRepo) GetByID(ctx context.Context, id int64) (db.Application, error) {
	app, err := gorm.G[db.Application](r.db).Where("id = ?", id).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return app, ErrNotFound
	}
	return app, err
}

func (r *gormApplicationRepo) List(ctx context.Context) ([]db.Application, error) {
	return gorm.G[db.Application](r.db).Find(ctx)
}

func (r *gormApplicationRepo) Update(ctx context.Context, app *db.Application) (db.Application, error) {
	rows, err := gorm.G[db.Application](r.db).
		Where("id = ?", app.ID).
		Select("*").
		Omit("id").
		Updates(ctx, *app)
	if err != nil {
		return *app, err
	}
	if rows == 0 {
		return *app, ErrNotFound
	}
	return *app, nil
}

func (r *gormApplicationRepo) GetWithClients(ctx context.Context, id int64) (db.Application, []db.OAuthClient, error) {
	app, err := r.GetByID(ctx, id)
	if err != nil {
		return app, nil, err
	}
	clients, err := gorm.G[db.OAuthClient](r.db).Where("application_id = ?", id).Find(ctx)
	return app, clients, err
}
