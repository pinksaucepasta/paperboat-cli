package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

const (
	readinessProbeTimeout = 3 * time.Second
	readinessProbeBodyMax = 8 << 10
)

// HostLifecycleConfig is the single composition boundary for the native
// services that make up a host installation. Keeping hostd and updated (and,
// on privileged Unix installs, the host service) in one manager gives them one
// durable journal and one cross-process lock, so a partially applied install
// cannot leave only one role active.
type HostLifecycleConfig struct {
	StateRoot    string
	Host         *Installer
	Hostd        *Installer
	Updater      *Installer
	HostProbe    func(context.Context) error
	HostdProbe   func(context.Context) error
	UpdaterProbe func(context.Context) error
}

// NewHostLifecycleManager constructs the durable hostd+updater transaction.
// Both installers must use native controllers. A plain Controller is rejected
// because it cannot report exact pre-state or restore enablement/running
// state after a failed phase.
func NewHostLifecycleManager(config HostLifecycleConfig) (*LifecycleManager, error) {
	if config.Hostd == nil || config.Updater == nil || config.Hostd == config.Updater || config.Host == config.Hostd || config.Host == config.Updater {
		return nil, ErrLifecycleInvalid
	}
	var host *NativeTransactionalComponent
	if config.Host != nil {
		hostController, ok := config.Host.config.Controller.(NativeLifecycleController)
		if !ok || hostController == nil {
			return nil, ErrLifecycleInvalid
		}
		var err error
		host, err = NewNativeTransactionalComponent(NativeTransactionalComponentConfig{
			Installer: config.Host, Controller: hostController, Probe: config.HostProbe,
		})
		if err != nil {
			return nil, err
		}
	}
	hostdController, ok := config.Hostd.config.Controller.(NativeLifecycleController)
	if !ok || hostdController == nil {
		return nil, ErrLifecycleInvalid
	}
	updaterController, ok := config.Updater.config.Controller.(NativeLifecycleController)
	if !ok || updaterController == nil {
		return nil, ErrLifecycleInvalid
	}
	hostd, err := NewNativeTransactionalComponent(NativeTransactionalComponentConfig{
		Installer: config.Hostd, Controller: hostdController, Probe: config.HostdProbe,
	})
	if err != nil {
		return nil, err
	}
	updater, err := NewNativeTransactionalComponent(NativeTransactionalComponentConfig{
		Installer: config.Updater, Controller: updaterController, Probe: config.UpdaterProbe,
	})
	if err != nil {
		return nil, err
	}
	components := []TransactionalComponent{hostd, updater}
	if host != nil {
		// The privileged host service owns the hostd supervisor and must be
		// prepared first. Stop/uninstall automatically reverse this order.
		components = []TransactionalComponent{host, hostd, updater}
	}
	return NewLifecycleManager(LifecycleConfig{StateRoot: config.StateRoot, Components: components})
}

// NativeComponent exposes an installer through the transactional native
// component boundary. It is useful to callers that compose a manager with a
// role-specific probe rather than using NewHostLifecycleManager.
func (i *Installer) NativeComponent(probe func(context.Context) error) (*NativeTransactionalComponent, error) {
	if i == nil {
		return nil, ErrLifecycleInvalid
	}
	controller, ok := i.config.Controller.(NativeLifecycleController)
	if !ok || controller == nil {
		return nil, ErrLifecycleInvalid
	}
	return NewNativeTransactionalComponent(NativeTransactionalComponentConfig{
		Installer: i, Controller: controller, Probe: probe,
	})
}

// NewHTTPReadinessProbe returns a bounded, loopback-only application probe for
// the hostd/updater /healthz endpoint. Native service state is not readiness:
// the response must be HTTP 200 and contain {"live":true}. Redirects,
// non-loopback URLs, oversized responses, malformed JSON, and trailing bytes
// fail closed.
func NewHTTPReadinessProbe(endpoint string) (func(context.Context) error, error) {
	return newHTTPReadinessProbe(endpoint, nil)
}

// NewHTTPReadinessProbeWithClient is the deterministic-test seam for
// NewHTTPReadinessProbe. The supplied client is copied and redirects remain
// disabled even when the caller provided a custom client.
func NewHTTPReadinessProbeWithClient(endpoint string, client *http.Client) (func(context.Context) error, error) {
	return newHTTPReadinessProbe(endpoint, client)
}

func newHTTPReadinessProbe(endpoint string, supplied *http.Client) (func(context.Context) error, error) {
	parsed, err := validateReadinessEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	var client *http.Client
	if supplied == nil {
		client, err = httptransport.NewLoopbackClient(readinessProbeTimeout)
		if err != nil {
			return nil, errors.Join(ErrLifecycleInvalid, err)
		}
	} else {
		clientCopy := *supplied
		client = &clientCopy
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		if client.Timeout == 0 || client.Timeout > readinessProbeTimeout {
			client.Timeout = readinessProbeTimeout
		}
	}
	return func(ctx context.Context) error {
		if ctx == nil {
			return ErrLifecycleInvalid
		}
		probeCtx, cancel := context.WithTimeout(ctx, readinessProbeTimeout)
		defer cancel()
		request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return errors.Join(ErrLifecycleNotReady, err)
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.Join(ErrLifecycleNotReady, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, readinessProbeBodyMax+1))
		closeErr := response.Body.Close()
		if readErr != nil {
			return errors.Join(ErrLifecycleNotReady, readErr, closeErr)
		}
		if closeErr != nil {
			return errors.Join(ErrLifecycleNotReady, closeErr)
		}
		contentTypes := response.Header.Values("Content-Type")
		mediaType := ""
		if len(contentTypes) == 1 {
			mediaType, _, _ = mime.ParseMediaType(contentTypes[0])
		}
		if response.StatusCode != http.StatusOK || len(contentTypes) != 1 || mediaType != "application/json" || len(body) == 0 || len(body) > readinessProbeBodyMax {
			return fmt.Errorf("%w: unexpected health response", ErrLifecycleNotReady)
		}
		if err := rejectDuplicateJSONFields(body); err != nil {
			return errors.Join(ErrLifecycleNotReady, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		var health struct {
			Live bool `json:"live"`
		}
		if err := decoder.Decode(&health); err != nil {
			return errors.Join(ErrLifecycleNotReady, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			if err == nil {
				return fmt.Errorf("%w: trailing health response", ErrLifecycleNotReady)
			}
			return errors.Join(ErrLifecycleNotReady, err)
		}
		if !health.Live {
			return fmt.Errorf("%w: application is not live", ErrLifecycleNotReady)
		}
		return nil
	}, nil
}

// rejectDuplicateJSONFields walks the bounded response before decoding it
// into a Go struct. encoding/json otherwise silently keeps the last duplicate
// key, which would make a health response such as {"live":false,"live":true}
// ambiguous at a security-sensitive readiness boundary.
func rejectDuplicateJSONFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				seen := make(map[string]struct{})
				for decoder.More() {
					keyToken, err := decoder.Token()
					if err != nil {
						return err
					}
					key, ok := keyToken.(string)
					if !ok {
						return errors.New("health response object key is not a string")
					}
					if _, duplicate := seen[key]; duplicate {
						return fmt.Errorf("duplicate health response field %q", key)
					}
					seen[key] = struct{}{}
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			default:
				return nil
			}
		default:
			return nil
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing health response")
		}
		return err
	}
	return nil
}

func validateReadinessEndpoint(endpoint string) (*url.URL, error) {
	if strings.TrimSpace(endpoint) != endpoint || endpoint == "" || len(endpoint) > 2048 {
		return nil, ErrLifecycleInvalid
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/healthz" || parsed.Opaque != "" {
		return nil, ErrLifecycleInvalid
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() || parsed.Port() == "" {
		return nil, ErrLifecycleInvalid
	}
	return parsed, nil
}
