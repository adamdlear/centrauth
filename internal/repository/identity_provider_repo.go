package repository

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type IdentityProviderRepository interface {
	ListByApplicationID(ctx context.Context, applicationID int64) ([]db.IdentityProvider, error)
	GetByApplicationAndProvider(ctx context.Context, applicationID int64, provider string) (db.IdentityProvider, error)
	Upsert(ctx context.Context, provider *db.IdentityProvider) (db.IdentityProvider, error)
	SetEnabled(ctx context.Context, applicationID int64, provider string, enabled bool) error
	Delete(ctx context.Context, applicationID int64, provider string) error
}

type gormIdentityProviderRepo struct {
	db *gorm.DB
}

func NewGormIdentityProviderRepo(db *gorm.DB) IdentityProviderRepository {
	return &gormIdentityProviderRepo{db: db}
}

func (r *gormIdentityProviderRepo) ListByApplicationID(ctx context.Context, applicationID int64) ([]db.IdentityProvider, error) {
	return gorm.G[db.IdentityProvider](r.db).
		Where("application_id = ?", applicationID).
		Order("provider").
		Find(ctx)
}

func (r *gormIdentityProviderRepo) GetByApplicationAndProvider(ctx context.Context, applicationID int64, provider string) (db.IdentityProvider, error) {
	found, err := gorm.G[db.IdentityProvider](r.db).
		Where("application_id = ?", applicationID).
		Where("provider = ?", provider).
		First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return found, ErrNotFound
	}
	return found, err
}

func (r *gormIdentityProviderRepo) Upsert(ctx context.Context, provider *db.IdentityProvider) (db.IdentityProvider, error) {
	err := gorm.G[db.IdentityProvider](r.db, clause.OnConflict{
		Columns: []clause.Column{{Name: "application_id"}, {Name: "provider"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"client_id",
			"client_secret_encrypted",
			"enabled",
			"updated_at",
		}),
	}).Create(ctx, provider)
	return *provider, err
}

func (r *gormIdentityProviderRepo) SetEnabled(ctx context.Context, applicationID int64, provider string, enabled bool) error {
	rows, err := gorm.G[db.IdentityProvider](r.db).
		Where("application_id = ?", applicationID).
		Where("provider = ?", provider).
		Update(ctx, "enabled", enabled)
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *gormIdentityProviderRepo) Delete(ctx context.Context, applicationID int64, provider string) error {
	rows, err := gorm.G[db.IdentityProvider](r.db).
		Where("application_id = ?", applicationID).
		Where("provider = ?", provider).
		Delete(ctx)
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}
