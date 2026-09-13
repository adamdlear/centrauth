package repository

import (
	"context"
	"errors"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type SessionRepository interface {
	Create(ctx context.Context, session *db.Session) (db.Session, error)
	GetByTokenHash(ctx context.Context, tokenHash []byte) (db.Session, error)
	Revoke(ctx context.Context, id int64) error
	RevokeAllForUser(ctx context.Context, userID int64) error
	DeleteInactive(ctx context.Context) (int, error)
}

type gormSessionRepo struct {
	db *gorm.DB
}

func NewGormSessionRepo(db *gorm.DB) SessionRepository {
	return &gormSessionRepo{db: db}
}

func (r *gormSessionRepo) Create(ctx context.Context, session *db.Session) (db.Session, error) {
	err := gorm.G[db.Session](r.db).Create(ctx, session)
	return *session, err
}

func (r *gormSessionRepo) GetByTokenHash(ctx context.Context, tokenHash []byte) (db.Session, error) {
	session, err := gorm.G[db.Session](r.db).Where("token_hash = ?", tokenHash).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return session, ErrNotFound
	}
	return session, err
}

func (r *gormSessionRepo) Revoke(ctx context.Context, id int64) error {
	rows, err := gorm.G[db.Session](r.db).Where("id = ?", id).Update(ctx, "revoked_at", time.Now())
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *gormSessionRepo) RevokeAllForUser(ctx context.Context, userID int64) error {
	_, err := gorm.G[db.Session](r.db).
		Where("user_id = ?", userID).
		Where("revoked_at IS NULL").
		Update(ctx, "revoked_at", time.Now())
	return err
}

func (r *gormSessionRepo) DeleteInactive(ctx context.Context) (int, error) {
	return gorm.G[db.Session](r.db).Where("expires_at < ? OR revoked_at IS NOT NULL", time.Now()).Delete(ctx)
}
