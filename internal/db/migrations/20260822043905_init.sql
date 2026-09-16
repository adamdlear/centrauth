-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id          bigint generated always as identity primary key,
    subject     text not null unique,
    email       citext not null unique,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

CREATE TABLE user_credentials (
    id             bigint generated always as identity primary key,
    user_id        bigint not null references users(id) on delete cascade,
    method         text not null,
    password_hash  text,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    unique(user_id, method)
);

CREATE TABLE sessions (
    id          bigint generated always as identity primary key,
    token_hash  bytea not null unique,
    user_id     bigint not null references users(id) on delete cascade,
    expires_at  timestamptz not null,
    revoked_at  timestamptz,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE applications (
    id             bigint generated always as identity primary key,
    name           text not null,
    description    text not null default '',
    first_party    boolean not null default true,
    allowed_scopes text[] not null default '{}',
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now()
);

CREATE TABLE oauth_clients (
    id                          bigint generated always as identity primary key,
    application_id              bigint not null references applications(id) on delete cascade,
    client_id                   text not null unique,
    client_secret_hash          bytea,
    client_type                 text not null check (client_type in ('confidential', 'public')),
    token_endpoint_auth_method  text not null default 'none'
                                check (token_endpoint_auth_method in ('client_secret_basic', 'client_secret_post', 'none')),
    redirect_uris               text[] not null default '{}',
    post_logout_redirect_uris   text[] not null default '{}',
    allowed_origins             text[] not null default '{}',
    environment                 text not null default 'local'
                                check (environment in ('local', 'staging', 'production')),
    created_at                  timestamptz not null default now(),
    updated_at                  timestamptz not null default now()
);

CREATE INDEX idx_oauth_clients_application_id ON oauth_clients (application_id);

CREATE TABLE oauth_authorization_codes (
    id               bigint generated always as identity primary key,
    code_hash        bytea not null unique,
    oauth_client_id  bigint not null references oauth_clients(id) on delete cascade,
    user_id          bigint not null references users(id) on delete cascade,
    expires_at       timestamptz not null,
    consumed_at      timestamptz,
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now()
);

CREATE INDEX idx_oauth_authorization_codes_expires_at ON oauth_authorization_codes (expires_at);

-- +goose Down
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS users;
DROP EXTENSION IF EXISTS citext;
