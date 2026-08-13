package networkcheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

func ProbeStack(ctx context.Context) (StackResult, error) {
	if ctx == nil {
		return StackResult{}, errors.New("invalid network stack probe")
	}
	result := StackResult{}
	ipv4, ipv4Err := udpsocket.Open(ctx, udpsocket.DevelopmentConfig(true, false))
	if ipv4Err == nil {
		result.IPv4 = true
		_ = ipv4.Close()
	}
	ipv6, ipv6Err := udpsocket.Open(ctx, udpsocket.DevelopmentConfig(false, true))
	if ipv6Err == nil {
		result.IPv6 = true
		_ = ipv6.Close()
	}
	result.UDP = result.IPv4 || result.IPv6
	if !result.UDP {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		return result, ErrUDPBlocked
	}
	return result, nil
}

func ProbeCaptivePortal(ctx context.Context, client *http.Client, endpoint string) (PortalResult, error) {
	if ctx == nil || client == nil {
		return PortalResult{}, errors.New("invalid captive portal probe")
	}
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return PortalResult{}, errors.New("invalid captive portal probe")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return PortalResult{}, errors.New("invalid captive portal probe")
	}
	request.Header.Set("Accept", "application/octet-stream")
	probeClient := &http.Client{Transport: client.Transport, Jar: nil, Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := probeClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PortalResult{}, ctxErr
		}
		return PortalResult{}, errors.Join(ErrUnreachable, err)
	}
	defer response.Body.Close()
	value, readErr := io.ReadAll(io.LimitReader(response.Body, 2))
	if readErr != nil {
		return PortalResult{}, errors.Join(ErrUnreachable, readErr)
	}
	return PortalResult{Complete: true, Suspected: response.StatusCode != http.StatusNoContent || len(value) != 0}, nil
}
