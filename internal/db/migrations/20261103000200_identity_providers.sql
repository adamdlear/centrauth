-- +goose Up
CREATE TABLE identity_providers (
    id                      bigint generated always as identity primary key,
    application_id          bigint not null references applications(id) on delete cascade,
    provider                text not null check (provider in ('google', 'github')),
    client_id               text not null,
    client_secret_encrypted bytea not null,
    enabled                 boolean not null default true,
    created_at              timestamptz not null default now(),
    updated_at              timestamptz not null default now(),
    unique (application_id, provider)
);

CREATE INDEX idx_identity_providers_application_id ON identity_providers (application_id);

CREATE TABLE user_identities (
    id                bigint generated always as identity primary key,
    user_id           bigint not null references users(id) on delete cascade,
    provider          text not null,
    provider_subject  text not null,
    email             text not null default '',
    email_verified    boolean not null default false,
    name              text not null default '',
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    unique (provider, provider_subject),
    unique (user_id, provider)
);

CREATE INDEX idx_user_identities_user_id ON user_identities (user_id);

-- +goose Down
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS identity_providers;
