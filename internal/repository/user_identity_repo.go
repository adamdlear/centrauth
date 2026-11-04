package repository

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type UserIdentityRepository interface {
	GetByProviderSubject(ctx context.Context, provider, subject string) (db.UserIdentity, error)
	ListByUserID(ctx context.Context, userID int64) ([]db.UserIdentity, error)
	Create(ctx context.Context, identity *db.UserIdentity) (db.UserIdentity, error)
	CreateWithUser(ctx context.Context, user *db.User, identity *db.UserIdentity) error
}

type gormUserIdentityRepo struct {
	db *gorm.DB
}

func NewGormUserIdentityRepo(db *gorm.DB) UserIdentityRepository {
	return &gormUserIdentityRepo{db: db}
}

func (r *gormUserIdentityRepo) GetByProviderSubject(ctx context.Context, provider, subject string) (db.UserIdentity, error) {
	found, err := gorm.G[db.UserIdentity](r.db).
		Where("provider = ?", provider).
		Where("provider_subject = ?", subject).
		First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return found, ErrNotFound
	}
	return found, err
}

func (r *gormUserIdentityRepo) ListByUserID(ctx context.Context, userID int64) ([]db.UserIdentity, error) {
	return gorm.G[db.UserIdentity](r.db).Where("user_id = ?", userID).Find(ctx)
}

func (r *gormUserIdentityRepo) Create(ctx context.Context, identity *db.UserIdentity) (db.UserIdentity, error) {
	err := gorm.G[db.UserIdentity](r.db).Create(ctx, identity)
	return *identity, err
}

func (r *gormUserIdentityRepo) CreateWithUser(ctx context.Context, user *db.User, identity *db.UserIdentity) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := gorm.G[db.User](tx).Create(ctx, user); err != nil {
			return err
		}
		identity.UserID = user.ID
		return gorm.G[db.UserIdentity](tx).Create(ctx, identity)
	})
}
