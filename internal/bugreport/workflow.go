package bugreport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

const ResultSchemaV1 = "paperboat.bugreport/v1"

type Local interface {
	RecordBugreportMarker(context.Context, string) error
	CreateBugreport(context.Context) (diagnostics.Bundle, error)
}

type Server interface {
	CreateDiagnosticUploadIntent(context.Context, string, api.DiagnosticUploadIntentRequest) (api.DiagnosticUploadIntent, error)
	UploadDiagnosticBundle(context.Context, api.DiagnosticUploadIntent, io.Reader, int64) error
	CompleteDiagnosticUploadIntent(context.Context, string) (api.DiagnosticUploadIntent, error)
}

type Options struct {
	Record       bool
	Upload       bool
	Input        io.Reader
	Prompt       io.Writer
	Local        Local
	Server       Server
	BeforeUpload func(Result) error
}

type Result struct {
	Schema              string    `json:"schema"`
	BundleCreated       bool      `json:"bundle_created"`
	CorrelationID       string    `json:"correlation_id,omitempty"`
	BundlePath          string    `json:"bundle_path,omitempty"`
	Bytes               int64     `json:"bytes,omitempty"`
	SHA256              string    `json:"sha256,omitempty"`
	Categories          []string  `json:"categories,omitempty"`
	CreatedAt           time.Time `json:"created_at,omitempty"`
	Recorded            bool      `json:"recorded"`
	Uploaded            bool      `json:"uploaded"`
	ServerCorrelationID string    `json:"server_correlation_id,omitempty"`
	Error               *Failure  `json:"error,omitempty"`
}

type Failure struct {
	Code    string `json:"code"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

func (r Result) Validate() error {
	if r.Schema != ResultSchemaV1 || r.Uploaded != (r.ServerCorrelationID != "") || r.Uploaded && !r.BundleCreated {
		return errors.New("invalid bugreport result")
	}
	if r.BundleCreated {
		if len(r.CorrelationID) != 35 || r.BundlePath == "" || r.Bytes < 1 || r.Bytes > diagnostics.MaximumBundleBytes || len(r.SHA256) != 64 || !slices.Equal(r.Categories, []string{"manifest", "recent_events", "redacted_events", "status"}) || r.CreatedAt.IsZero() || r.CreatedAt.Location() != time.UTC {
			return errors.New("invalid bugreport bundle result")
		}
	} else if r.CorrelationID != "" || r.BundlePath != "" || r.Bytes != 0 || r.SHA256 != "" || len(r.Categories) != 0 || !r.CreatedAt.IsZero() || r.Uploaded {
		return errors.New("bundle fields are present without a bundle")
	}
	if r.Error != nil && (r.Error.Code == "" || r.Error.Stage == "" || r.Error.Message == "" || len(r.Error.Code) > 64 || len(r.Error.Stage) > 128 || len(r.Error.Message) > 512) {
		return errors.New("invalid bugreport failure")
	}
	return nil
}

type StageError struct {
	Stage  string
	Result Result
	Err    error
}

func (e *StageError) Error() string { return fmt.Sprintf("%s: %v", e.Stage, e.Err) }
func (e *StageError) Unwrap() error { return e.Err }

func Run(ctx context.Context, options Options) (Result, error) {
	result := Result{Schema: ResultSchemaV1}
	if ctx == nil || options.Local == nil || options.Input == nil || options.Prompt == nil || options.Upload && options.Server == nil {
		return result, errors.New("invalid bugreport workflow")
	}
	markerErr := error(nil)
	if options.Record {
		if err := options.Local.RecordBugreportMarker(ctx, "start"); err != nil {
			return result, &StageError{Stage: "start reproduction recording", Result: result, Err: err}
		}
		_, _ = fmt.Fprintln(options.Prompt, "Reproduce the issue, then press Enter to finish recording.")
		readErr := waitForLine(ctx, options.Input)
		endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		endErr := options.Local.RecordBugreportMarker(endCtx, "end")
		cancel()
		markerErr = errors.Join(readErr, endErr)
		result.Recorded = markerErr == nil
	}
	bundle, err := options.Local.CreateBugreport(ctx)
	if err != nil {
		return result, &StageError{Stage: "create local bundle", Result: result, Err: errors.Join(markerErr, err)}
	}
	result.BundleCreated, result.CorrelationID, result.BundlePath, result.Bytes, result.Categories, result.CreatedAt = true, bundle.Correlation, bundle.Path, bundle.Bytes, slices.Clone(bundle.Categories), bundle.CreatedAt
	file, err := openExactBundle(bundle)
	if err != nil {
		return result, &StageError{Stage: "open local bundle", Result: result, Err: errors.Join(markerErr, err)}
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, &StageError{Stage: "hash local bundle", Result: result, Err: errors.Join(markerErr, err)}
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	if markerErr != nil {
		return result, &StageError{Stage: "finish reproduction recording", Result: result, Err: markerErr}
	}
	if !options.Upload {
		return result, nil
	}
	if options.BeforeUpload != nil {
		if err := options.BeforeUpload(result); err != nil {
			return result, &StageError{Stage: "display upload categories", Result: result, Err: err}
		}
	}
	operationKey, err := randomOperationKey()
	if err != nil {
		return result, &StageError{Stage: "authorize upload", Result: result, Err: err}
	}
	intent, err := options.Server.CreateDiagnosticUploadIntent(ctx, operationKey, api.DiagnosticUploadIntentRequest{Schema: api.DiagnosticUploadIntentRequestSchemaV1, CorrelationID: result.CorrelationID, Bytes: result.Bytes, SHA256: result.SHA256, Categories: slices.Clone(result.Categories)})
	if err != nil {
		return result, &StageError{Stage: "authorize upload", Result: result, Err: err}
	}
	if intent.CorrelationID != result.CorrelationID {
		return result, &StageError{Stage: "authorize upload", Result: result, Err: errors.New("server correlation does not match the local bundle")}
	}
	if intent.State == "pending" {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return result, &StageError{Stage: "upload bundle", Result: result, Err: err}
		}
		if err := options.Server.UploadDiagnosticBundle(ctx, intent, file, result.Bytes); err != nil {
			return result, &StageError{Stage: "upload bundle", Result: result, Err: err}
		}
	}
	completed, err := options.Server.CompleteDiagnosticUploadIntent(ctx, intent.IntentID)
	if err != nil {
		return result, &StageError{Stage: "finalize upload", Result: result, Err: err}
	}
	if completed.CorrelationID != result.CorrelationID || completed.State != "uploaded" {
		return result, &StageError{Stage: "finalize upload", Result: result, Err: errors.New("server returned a mismatched diagnostic upload completion")}
	}
	result.Uploaded, result.ServerCorrelationID = true, completed.CorrelationID
	return result, nil
}

func waitForLine(ctx context.Context, input io.Reader) error {
	done := make(chan error, 1)
	go func() {
		_, err := bufio.NewReader(input).ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func openExactBundle(bundle diagnostics.Bundle) (*os.File, error) {
	if bundle.Validate() != nil {
		return nil, errors.New("local daemon returned an invalid bundle")
	}
	pathInfo, err := os.Lstat(bundle.Path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 || pathInfo.Size() != bundle.Bytes {
		return nil, errors.Join(errors.New("local diagnostic bundle is unsafe or changed"), err)
	}
	file, err := os.Open(bundle.Path)
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, fileInfo) || fileInfo.Size() != bundle.Bytes {
		_ = file.Close()
		return nil, errors.Join(errors.New("local diagnostic bundle changed while opening"), err)
	}
	return file, nil
}

func randomOperationKey() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "diagnostic_" + hex.EncodeToString(value[:]), nil
}
