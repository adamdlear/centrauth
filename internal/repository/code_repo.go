package repository

import (
	"context"
	"errors"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type CodeRepository interface {
	Create(ctx context.Context, code *db.OAuthAuthorizationCode) (db.OAuthAuthorizationCode, error)
	GetByCodeHash(ctx context.Context, codeHash []byte) (db.OAuthAuthorizationCode, error)
	Consume(ctx context.Context, id int64) error
}

type gormCodeRepo struct {
	db *gorm.DB
}

func NewGormCodeRepo(db *gorm.DB) CodeRepository {
	return &gormCodeRepo{db: db}
}

func (r *gormCodeRepo) Create(ctx context.Context, code *db.OAuthAuthorizationCode) (db.OAuthAuthorizationCode, error) {
	err := gorm.G[db.OAuthAuthorizationCode](r.db).Create(ctx, code)
	return *code, err
}

func (r *gormCodeRepo) GetByCodeHash(ctx context.Context, codeHash []byte) (db.OAuthAuthorizationCode, error) {
	code, err := gorm.G[db.OAuthAuthorizationCode](r.db).Where("code_hash = ?", codeHash).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return code, ErrNotFound
	}
	return code, err
}

func (r *gormCodeRepo) Consume(ctx context.Context, id int64) error {
	rows, err := gorm.G[db.OAuthAuthorizationCode](r.db).
		Where("id = ?", id).
		Where("consumed_at IS NULL").
		Update(ctx, "consumed_at", time.Now())
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}
