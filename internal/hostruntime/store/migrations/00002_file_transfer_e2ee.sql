-- +goose Up
ALTER TABLE file_transfers ADD COLUMN e2ee_transfer_id TEXT CHECK(e2ee_transfer_id IS NULL OR length(e2ee_transfer_id) BETWEEN 1 AND 128);
ALTER TABLE file_transfers ADD COLUMN transfer_generation INTEGER CHECK(transfer_generation IS NULL OR transfer_generation > 0);
ALTER TABLE file_transfers ADD COLUMN file_ordinal INTEGER CHECK(file_ordinal IS NULL OR file_ordinal >= 0);
ALTER TABLE file_transfers ADD COLUMN committed_chunks INTEGER NOT NULL DEFAULT 0 CHECK(committed_chunks >= 0);
CREATE TABLE file_transfer_chunks(transfer_id TEXT NOT NULL REFERENCES file_transfers(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL CHECK(ordinal >= 0),ciphertext_sha256 BLOB NOT NULL CHECK(length(ciphertext_sha256)=32),ciphertext_length INTEGER NOT NULL CHECK(ciphertext_length BETWEEN 16 AND 1048592),plaintext_length INTEGER NOT NULL CHECK(plaintext_length BETWEEN 0 AND 1048576),PRIMARY KEY(transfer_id,ordinal)) STRICT;
PRAGMA user_version=2;

-- +goose Down
DROP TABLE file_transfer_chunks;
ALTER TABLE file_transfers DROP COLUMN committed_chunks;
ALTER TABLE file_transfers DROP COLUMN file_ordinal;
ALTER TABLE file_transfers DROP COLUMN transfer_generation;
ALTER TABLE file_transfers DROP COLUMN e2ee_transfer_id;
PRAGMA user_version=1;
