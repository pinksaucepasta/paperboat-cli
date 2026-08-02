-- name: CreateSession :exec
INSERT INTO sessions(id,name,cwd,command_path,command_args,command_env,columns,rows,state,generation,exit_code,exit_signal,exited_at,earliest_sequence,latest_sequence,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: ListSessions :many
SELECT id,name,cwd,command_path,command_args,command_env,columns,rows,state,generation,exit_code,COALESCE(exit_signal,''),exited_at,earliest_sequence,latest_sequence,created_at,updated_at FROM sessions ORDER BY name;

-- name: SessionBounds :one
SELECT earliest_sequence,latest_sequence FROM sessions WHERE id=?;

-- name: DeleteClosedSession :execrows
DELETE FROM sessions WHERE id=? AND state IN ('exited','closed');

-- name: FileTransfer :one
SELECT * FROM file_transfers WHERE id=?;

-- name: FileTransfersByBatch :many
SELECT * FROM file_transfers WHERE batch_id=? ORDER BY created_at,id;

-- name: PendingFileTransfers :many
SELECT * FROM file_transfers WHERE delivery_client_id=? AND session_id=? AND state='pending' AND expires_at>? ORDER BY created_at,id LIMIT ?;

-- name: ExpiredFileTransfers :many
SELECT * FROM file_transfers WHERE expires_at<=? AND state IN ('created','uploading','published','pending') ORDER BY expires_at,id LIMIT 100;

-- name: DeleteExpiredOperations :exec
DELETE FROM operation_results WHERE expires_at<=?;

-- name: ResetOversizedOperations :exec
UPDATE operation_results SET state='pending',result=NULL,error_code=NULL,completed_at=NULL WHERE length(result)>CAST(sqlc.arg(max_bytes) AS INTEGER);

-- name: ListOperations :many
SELECT operation_id,request_hash,state,result,COALESCE(error_code,''),completed_at,expires_at FROM operation_results ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END,completed_at ASC LIMIT ?;

-- name: GetOperation :one
SELECT operation_id,request_hash,state,result,COALESCE(error_code,''),completed_at,expires_at FROM operation_results WHERE operation_id=?;

-- name: ListInputDecisions :many
SELECT session_id,client_id,attachment_id,generation,input_id,request_hash,status,bytes_written,COALESCE(error_code,''),created_at FROM input_decisions WHERE session_id=? ORDER BY generation,created_at;

-- name: ReplayOutput :many
SELECT channel,start_sequence,end_sequence,data FROM output_events WHERE session_id=? AND end_sequence>? ORDER BY start_sequence;
