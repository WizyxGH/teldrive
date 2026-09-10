-- +goose Up
-- A link no longer only allows uploads: write access = upload files, create
-- folders, rename.
ALTER TABLE teldrive.file_shares RENAME COLUMN allow_upload TO writable;

-- +goose Down
ALTER TABLE teldrive.file_shares RENAME COLUMN writable TO allow_upload;
