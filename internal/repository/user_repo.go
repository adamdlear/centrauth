package repository

import (
	"context"
	"errors"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (db.User, error)
	GetByID(ctx context.Context, id int64) (db.User, error)
	Create(ctx context.Context, user *db.User) (db.User, error)
	CreateWithCredential(ctx context.Context, user *db.User, cred *db.UserCredential) (db.User, error)
}

type gormUserRepo struct {
	db *gorm.DB
}

func NewGormUserRepo(db *gorm.DB) UserRepository {
	return &gormUserRepo{db: db}
}

func (r *gormUserRepo) GetByEmail(ctx context.Context, email string) (db.User, error) {
	user, err := gorm.G[db.User](r.db).Where("email = ?", email).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return user, ErrNotFound
	}
	return user, err
}

func (r *gormUserRepo) GetByID(ctx context.Context, id int64) (db.User, error) {
	user, err := gorm.G[db.User](r.db).Where("id = ?", id).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return user, ErrNotFound
	}
	return user, err
}

func (r *gormUserRepo) Create(ctx context.Context, user *db.User) (db.User, error) {
	err := gorm.G[db.User](r.db).Create(ctx, user)
	return *user, err
}

func (r *gormUserRepo) CreateWithCredential(ctx context.Context, user *db.User, cred *db.UserCredential) (db.User, error) {
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := gorm.G[db.User](tx).Create(ctx, user); err != nil {
			return err
		}
		cred.UserID = user.ID
		err := gorm.G[db.UserCredential](tx).Create(ctx, cred)
		return err
	})
	return *user, err
}
