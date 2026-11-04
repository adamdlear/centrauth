-- +goose Up
ALTER TABLE oauth_authorization_codes ADD COLUMN redirect_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_authorization_codes ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_authorization_codes ADD COLUMN nonce TEXT;
ALTER TABLE oauth_authorization_codes ADD COLUMN code_challenge TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_authorization_codes ADD COLUMN code_challenge_method TEXT NOT NULL DEFAULT 'S256';

ALTER TABLE oauth_authorization_codes ADD CONSTRAINT oauth_authorization_codes_code_challenge_method_check
    CHECK (code_challenge_method IN ('S256'));

-- +goose Down
ALTER TABLE oauth_authorization_codes DROP CONSTRAINT IF EXISTS oauth_authorization_codes_code_challenge_method_check;
ALTER TABLE oauth_authorization_codes
    DROP COLUMN code_challenge_method,
    DROP COLUMN code_challenge,
    DROP COLUMN nonce,
    DROP COLUMN scope,
    DROP COLUMN redirect_uri;
