package db

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DBConfig struct {
	Host     string
	User     string
	Password string
	DBName   string
	Port     int
}

type DB struct {
	Client *gorm.DB
}

func New(cfg DBConfig) (*DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d", cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return &DB{}, err
	}
	return &DB{Client: db}, nil
}

func (d *DB) Close() error {
	sqlDB, err := d.Client.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
