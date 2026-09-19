-- +goose Up
CREATE TABLE operators (
    id            bigint generated always as identity primary key,
    email         citext not null unique,
    password_hash text not null,
    created_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now()
);

CREATE TABLE operator_sessions (
    id          bigint generated always as identity primary key,
    token_hash  bytea not null unique,
    operator_id bigint not null references operators(id) on delete cascade,
    expires_at  timestamptz not null,
    revoked_at  timestamptz,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

CREATE INDEX idx_operator_sessions_expires_at ON operator_sessions (expires_at);

-- +goose Down
DROP TABLE IF EXISTS operator_sessions;
DROP TABLE IF EXISTS operators;
