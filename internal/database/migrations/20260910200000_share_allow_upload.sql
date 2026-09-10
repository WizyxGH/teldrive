-- +goose Up
ALTER TABLE teldrive.file_shares ADD COLUMN IF NOT EXISTS allow_upload boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE teldrive.file_shares DROP COLUMN IF EXISTS allow_upload;
