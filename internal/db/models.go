package db

import (
	"time"

	pq "github.com/lib/pq"
)

type User struct {
	ID        int64     `gorm:"primaryKey;autoIncrement"`
	Subject   string    `gorm:"uniqueIndex;not null"`
	Email     string    `gorm:"uniqueIndex;not null;type:citext"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (User) TableName() string { return "users" }

type UserCredential struct {
	ID           int64     `gorm:"primaryKey;autoIncrement"`
	UserID       int64     `gorm:"column:user_id;not null;uniqueIndex:idx_user_credentials_user_method"`
	Method       string    `gorm:"not null;uniqueIndex:idx_user_credentials_user_method"`
	PasswordHash *string   `gorm:"column:password_hash"`
	CreatedAt    time.Time `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}

func (UserCredential) TableName() string { return "user_credentials" }

type Session struct {
	ID        int64      `gorm:"primaryKey;autoIncrement"`
	TokenHash []byte     `gorm:"column:token_hash;not null;uniqueIndex"`
	UserID    int64      `gorm:"column:user_id;not null;index"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null;index"`
	RevokedAt *time.Time `gorm:"column:revoked_at"`
	CreatedAt time.Time  `gorm:"not null"`
	UpdatedAt time.Time  `gorm:"not null"`
}

func (Session) TableName() string { return "sessions" }

type OAuthClient struct {
	ID                      int64          `gorm:"primaryKey;autoIncrement"`
	ClientID                string         `gorm:"column:client_id;not null;uniqueIndex"`
	ClientSecretHash        []byte         `gorm:"column:client_secret_hash"`
	ClientType              string         `gorm:"column:client_type;not null"`
	Name                    string         `gorm:"column:name;not null"`
	Description             string         `gorm:"column:description"`
	TokenEndpointAuthMethod string         `gorm:"column:token_endpoint_auth_method;not null;default:none"`
	RedirectURIs            pq.StringArray `gorm:"column:redirect_uris;type:text[];not null;default:'{}'"`
	PostLogoutRedirectURIs  pq.StringArray `gorm:"column:post_logout_redirect_uris;type:text[];not null;default:'{}'"`
	AllowedOrigins          pq.StringArray `gorm:"column:allowed_origins;type:text[];not null;default:'{}'"`
	AllowedScopes           pq.StringArray `gorm:"column:allowed_scopes;type:text[];not null;default:'{}'"`
	Environment             string         `gorm:"column:environment;not null;default:local"`
	FirstParty              bool           `gorm:"column:first_party;not null;default:true"`
	CreatedAt               time.Time      `gorm:"not null"`
	UpdatedAt               time.Time      `gorm:"not null"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

type OAuthAuthorizationCode struct {
	ID            int64      `gorm:"primaryKey;autoIncrement"`
	CodeHash      []byte     `gorm:"column:code_hash;not null;uniqueIndex"`
	OAuthClientID int64      `gorm:"column:oauth_client_id;not null"`
	UserID        int64      `gorm:"column:user_id;not null"`
	ExpiresAt     time.Time  `gorm:"column:expires_at;not null;index"`
	ConsumedAt    *time.Time `gorm:"column:consumed_at"`
	CreatedAt     time.Time  `gorm:"not null"`
	UpdatedAt     time.Time  `gorm:"not null"`
}

func (OAuthAuthorizationCode) TableName() string { return "oauth_authorization_codes" }
