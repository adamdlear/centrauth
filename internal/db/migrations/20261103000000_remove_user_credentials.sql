-- +goose Up

-- Application users authenticate through brokered identity providers only, so
-- password credentials no longer exist for them. Operator passwords live in
-- the separate operators table.
DROP TABLE IF EXISTS user_credentials;

-- +goose Down
CREATE TABLE user_credentials (
    id             bigint generated always as identity primary key,
    user_id        bigint not null references users(id) on delete cascade,
    method         text not null,
    password_hash  text,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    unique(user_id, method)
);
