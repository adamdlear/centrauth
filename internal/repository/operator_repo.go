package repository

import (
	"context"
	"errors"
	"hash/fnv"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

const setupSeatKey = "centrauth:setup_seat"

var ErrSeatTaken = errors.New("seat is already taken")

type OperatorRepository interface {
	GetByEmail(ctx context.Context, email string) (db.Operator, error)
	GetByID(ctx context.Context, id int64) (db.Operator, error)
	Count(ctx context.Context) (int64, error)
	CreateFirstOperator(ctx context.Context, operator *db.Operator) (db.Operator, error)
}

type gormOperatorRepo struct {
	db *gorm.DB
}

func NewGormOperatorRepo(db *gorm.DB) OperatorRepository {
	return &gormOperatorRepo{db: db}
}

func (r *gormOperatorRepo) create(ctx context.Context, tx *gorm.DB, operator *db.Operator) (db.Operator, error) {
	err := gorm.G[db.Operator](tx).Create(ctx, operator)
	return *operator, err
}

func (r *gormOperatorRepo) GetByEmail(ctx context.Context, email string) (db.Operator, error) {
	operator, err := gorm.G[db.Operator](r.db).Where("email = ?", email).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return operator, ErrNotFound
	}
	return operator, err
}

func (r *gormOperatorRepo) GetByID(ctx context.Context, id int64) (db.Operator, error) {
	operator, err := gorm.G[db.Operator](r.db).Where("id = ?", id).First(ctx)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return operator, ErrNotFound
	}
	return operator, err
}

func (r *gormOperatorRepo) Count(ctx context.Context) (int64, error) {
	return gorm.G[db.Operator](r.db).Count(ctx, "*")
}

func (r *gormOperatorRepo) countTx(ctx context.Context, tx *gorm.DB) (int64, error) {
	return gorm.G[db.Operator](tx).Count(ctx, "*")
}

func (r *gormOperatorRepo) CreateFirstOperator(ctx context.Context, operator *db.Operator) (db.Operator, error) {
	h := fnv.New64a()
	h.Write([]byte(setupSeatKey))
	key := int64(h.Sum64())
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", key).Error; err != nil {
			return err
		}
		count, err := r.countTx(ctx, tx)
		if err != nil {
			return err
		}
		if count > 0 {
			return ErrSeatTaken
		}
		_, err = r.create(ctx, tx, operator)
		return err
	})
	return *operator, err
}
