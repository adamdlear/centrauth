-- +goose Up
ALTER TABLE oauth_clients ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none';
ALTER TABLE oauth_clients ADD COLUMN post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_clients ADD COLUMN allowed_origins TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_clients ADD COLUMN allowed_scopes TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_clients ADD COLUMN environment TEXT NOT NULL DEFAULT 'local';
ALTER TABLE oauth_clients ADD COLUMN first_party BOOLEAN NOT NULL DEFAULT true;

-- Add check constraint for token_endpoint_auth_method
ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_token_endpoint_auth_method_check 
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none'));

-- Add check constraint for environment
ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_environment_check 
    CHECK (environment IN ('local', 'staging', 'production'));

-- +goose Down
ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_environment_check;
ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_token_endpoint_auth_method_check;
ALTER TABLE oauth_clients 
    DROP COLUMN first_party,
    DROP COLUMN environment,
    DROP COLUMN allowed_scopes,
    DROP COLUMN allowed_origins,
    DROP COLUMN post_logout_redirect_uris,
    DROP COLUMN token_endpoint_auth_method,
    DROP COLUMN description,
    DROP COLUMN name;
