package repository

import (
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/adamdlear/centrauth/internal/db"
	"gorm.io/gorm"
)

var (
	testDBOnce sync.Once
	testDB     *db.DB
	testDBErr  error
)

func newTestTx(t *testing.T) *gorm.DB {
	t.Helper()

	if os.Getenv("DB_HOST") == "" || os.Getenv("DB_DATABASE") == "" {
		t.Skip("DB_HOST/DB_DATABASE not set; skipping database tests")
	}

	testDBOnce.Do(func() {
		port := 5432
		if p := os.Getenv("DB_PORT"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				port = v
			}
		}
		testDB, testDBErr = db.New(db.DBConfig{
			Host:     os.Getenv("DB_HOST"),
			User:     os.Getenv("DB_USERNAME"),
			Password: os.Getenv("DB_PASSWORD"),
			DBName:   os.Getenv("DB_DATABASE"),
			Port:     port,
		})
	})
	if testDBErr != nil {
		t.Fatalf("connecting to test database: %v", testDBErr)
	}

	tx := testDB.Client.Begin()
	if tx.Error != nil {
		t.Fatalf("beginning transaction: %v", tx.Error)
	}
	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Logf("rolling back test transaction: %v", err)
		}
	})

	return tx
}

func seedUser(t *testing.T, tx *gorm.DB, u db.User) db.User {
	t.Helper()
	if err := tx.Create(&u).Error; err != nil {
		t.Fatalf("seeding user: %v", err)
	}
	return u
}

func seedCredential(t *testing.T, tx *gorm.DB, c db.UserCredential) db.UserCredential {
	t.Helper()
	if err := tx.Create(&c).Error; err != nil {
		t.Fatalf("seeding credential: %v", err)
	}
	return c
}

func seedSession(t *testing.T, tx *gorm.DB, s db.Session) db.Session {
	t.Helper()
	if err := tx.Create(&s).Error; err != nil {
		t.Fatalf("seeding session: %v", err)
	}
	return s
}

func seedClient(t *testing.T, tx *gorm.DB, c db.OAuthClient) db.OAuthClient {
	t.Helper()
	if err := tx.Create(&c).Error; err != nil {
		t.Fatalf("seeding oauth client: %v", err)
	}
	return c
}

func seedCode(t *testing.T, tx *gorm.DB, c db.OAuthAuthorizationCode) db.OAuthAuthorizationCode {
	t.Helper()
	if err := tx.Create(&c).Error; err != nil {
		t.Fatalf("seeding authorization code: %v", err)
	}
	return c
}
