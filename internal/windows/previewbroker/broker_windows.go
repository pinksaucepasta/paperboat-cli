//go:build windows

package previewbroker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const PipeName = `\\.\pipe\PaperboatPreviewBroker`
const tokenBytes = 32
const maxPayload = 64 << 10

var ErrUnavailable = errors.New("Windows preview service broker is unavailable")
var ErrUnauthorized = errors.New("Windows preview service broker rejected the request")
var ErrRejected = errors.New("Windows preview service operation failed")

func DeriveToken(installationToken []byte) []byte {
	if len(installationToken) != tokenBytes {
		return nil
	}
	mac := hmac.New(sha256.New, installationToken)
	_, _ = mac.Write([]byte("paperboat/windows/preview-broker/v1"))
	return mac.Sum(nil)
}

type Server struct {
	OwnerSID string
	Token    []byte
	Handle   func(context.Context, []byte) error
	Ready    chan<- struct{}
	PipeName string
}

func (s Server) Run(ctx context.Context) error {
	if !validSID(s.OwnerSID) || len(s.Token) != tokenBytes || s.Handle == nil {
		return ErrUnavailable
	}
	pipeName := s.PipeName
	if pipeName == "" {
		pipeName = PipeName
	}
	listener, err := winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GRGW;;;SY)(A;;GRGW;;;" + s.OwnerSID + ")", InputBufferSize: maxPayload + tokenBytes + 4, OutputBufferSize: 4096})
	if err != nil {
		return err
	}
	defer listener.Close()
	if s.Ready != nil {
		close(s.Ready)
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	defer workers.Wait()
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) || errors.Is(acceptErr, winio.ErrPipeListenerClosed) {
				return nil
			}
			return acceptErr
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-semaphore }(); s.serve(ctx, conn) }()
		default:
			_ = conn.Close()
		}
	}
}

func (s Server) serve(parent context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if sid, err := clientSID(conn); err != nil || sid != s.OwnerSID {
		return
	}
	token := make([]byte, tokenBytes)
	if _, err := io.ReadFull(conn, token); err != nil || subtle.ConstantTimeCompare(token, s.Token) != 1 {
		return
	}
	payload, err := readFrame(conn, maxPayload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	err = s.Handle(ctx, payload)
	response := struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}{OK: err == nil}
	if err != nil {
		response.Error = bounded(err.Error(), 2048)
	}
	body, _ := json.Marshal(response)
	_ = writeFrame(conn, body)
}

func Request(ctx context.Context, ownerSID string, token, payload []byte) error {
	return requestPipe(ctx, PipeName, ownerSID, token, payload)
}

func requestPipe(ctx context.Context, pipeName, ownerSID string, token, payload []byte) error {
	if !validSID(ownerSID) || len(token) != tokenBytes || len(payload) == 0 || len(payload) > maxPayload {
		return ErrUnavailable
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeAccessImpLevel(dialCtx, pipeName, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err = writeAll(conn, token); err == nil {
		err = writeFrame(conn, payload)
	}
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	body, err := readFrame(conn, 4096)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	var response struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil || response.OK == (response.Error != "") {
		return ErrUnavailable
	}
	if !response.OK {
		return fmt.Errorf("%w: %s", ErrRejected, response.Error)
	}
	return nil
}

func readFrame(r io.Reader, maximum uint32) ([]byte, error) {
	var size uint32
	if binary.Read(r, binary.LittleEndian, &size) != nil || size == 0 || size > maximum {
		return nil, ErrUnavailable
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > maxPayload {
		return ErrUnavailable
	}
	var h [4]byte
	binary.LittleEndian.PutUint32(h[:], uint32(len(b)))
	if err := writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func bounded(v string, n int) string {
	v = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, v)
	if len(v) > n {
		return v[:n]
	}
	return v
}
func validSID(v string) bool {
	sid, err := windows.StringToSid(v)
	return err == nil && sid != nil && sid.IsValid() && sid.String() == v
}

var impersonate = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func clientSID(conn net.Conn) (string, error) {
	withHandle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", ErrUnauthorized
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, callErr := impersonate.Call(withHandle.Fd())
	if result == 0 {
		return "", callErr
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic(err)
		}
	}()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", ErrUnauthorized
	}
	return user.User.Sid.String(), nil
}
