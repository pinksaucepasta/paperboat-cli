-- +goose Up
CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,cwd TEXT NOT NULL,command_path TEXT NOT NULL,command_args BLOB NOT NULL,command_env BLOB NOT NULL,columns INTEGER NOT NULL CHECK(columns BETWEEN 1 AND 1000),rows INTEGER NOT NULL CHECK(rows BETWEEN 1 AND 1000),state TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>=0),exit_code INTEGER,exit_signal TEXT,exited_at INTEGER,earliest_sequence INTEGER NOT NULL CHECK(earliest_sequence>=0),latest_sequence INTEGER NOT NULL CHECK(latest_sequence>=earliest_sequence),created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE output_events(session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,start_sequence INTEGER NOT NULL,end_sequence INTEGER NOT NULL,channel INTEGER NOT NULL CHECK(channel IN (1,2)),data BLOB NOT NULL CHECK(length(data)=end_sequence-start_sequence),PRIMARY KEY(session_id,start_sequence)) STRICT;
CREATE TABLE input_decisions(session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,client_id TEXT NOT NULL,attachment_id TEXT NOT NULL,generation INTEGER NOT NULL,input_id TEXT NOT NULL,request_hash BLOB NOT NULL,status TEXT NOT NULL,bytes_written INTEGER NOT NULL,error_code TEXT,created_at INTEGER NOT NULL,PRIMARY KEY(session_id,client_id,attachment_id,generation,input_id)) STRICT;
CREATE TABLE operation_results(operation_id TEXT PRIMARY KEY,request_hash BLOB NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','completed')),result BLOB,error_code TEXT,completed_at INTEGER,expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE file_transfers(id TEXT PRIMARY KEY,batch_id TEXT NOT NULL,source_machine_id TEXT NOT NULL,destination_machine_id TEXT NOT NULL,initiating_user_id TEXT NOT NULL,session_id TEXT,delivery_client_id TEXT,basename TEXT NOT NULL,size INTEGER NOT NULL CHECK(size BETWEEN 0 AND 52428800),sha256 TEXT NOT NULL CHECK(length(sha256)=64),committed_offset INTEGER NOT NULL CHECK(committed_offset BETWEEN 0 AND size),state TEXT NOT NULL CHECK(state IN ('created','uploading','published','pending','delivered','failed','canceled')),result_code TEXT,receipt_path TEXT,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX file_transfers_pending ON file_transfers(delivery_client_id,session_id,created_at) WHERE state='pending';
CREATE INDEX file_transfers_expiry ON file_transfers(expires_at);
PRAGMA user_version=1;

-- +goose Down
DROP TABLE file_transfers;
DROP TABLE operation_results;
DROP TABLE input_decisions;
DROP TABLE output_events;
DROP TABLE sessions;
PRAGMA user_version=0;
