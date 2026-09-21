package repository

import (
	"context"
	"errors"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type OperatorSessionRepository interface {
	Create(ctx context.Context, session *db.OperatorSession) (db.OperatorSession, error)
	GetByTokenHash(ctx context.Context, tokenHash []byte) (db.OperatorSession, error)
	Revoke(ctx context.Context, id int64) error
	RevokeAllForOperator(ctx context.Context, operatorID int64) error
	DeleteInactive(ctx context.Context) (int, error)
}

type gormOperatorSessionRepo struct {
	db *gorm.DB
}

func NewGormOperatorSessionRepo(db *gorm.DB) OperatorSessionRepository {
	return &gormOperatorSessionRepo{db: db}
}

func (r *gormOperatorSessionRepo) Create(ctx context.Context, session *db.OperatorSession) (db.OperatorSession, error) {
	err := gorm.G[db.OperatorSession](r.db).Create(ctx, session)
	return *session, err
}

func (r *gormOperatorSessionRepo) GetByTokenHash(ctx context.Context, tokenHash []byte) (db.OperatorSession, error) {
	session, err := gorm.G[db.OperatorSession](r.db).Where("token_hash = ?", tokenHash).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return session, ErrNotFound
	}
	return session, err
}

func (r *gormOperatorSessionRepo) Revoke(ctx context.Context, id int64) error {
	rows, err := gorm.G[db.OperatorSession](r.db).Where("id = ?", id).Update(ctx, "revoked_at", time.Now())
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *gormOperatorSessionRepo) RevokeAllForOperator(ctx context.Context, operatorID int64) error {
	_, err := gorm.G[db.OperatorSession](r.db).
		Where("operator_id = ?", operatorID).
		Where("revoked_at IS NULL").
		Update(ctx, "revoked_at", time.Now())
	return err
}

func (r *gormOperatorSessionRepo) DeleteInactive(ctx context.Context) (int, error) {
	return gorm.G[db.OperatorSession](r.db).Where("expires_at < ? OR revoked_at IS NOT NULL", time.Now()).Delete(ctx)
}
