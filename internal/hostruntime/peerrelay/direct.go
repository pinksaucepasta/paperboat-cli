package peerrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/candidatelease"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/directpath"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func directFailureAllowsFallback(ctx context.Context, err error) bool {
	if err == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	var failure *connectionmanager.Failure
	if errors.As(err, &failure) {
		return failure.AllowsFallback()
	}
	if errors.Is(err, directpath.ErrReachability) || errors.Is(err, directpath.ErrDescriptorUnavailable) || errors.Is(err, iceagent.ErrConnectionFailed) || errors.Is(err, iceagent.ErrConnectionClosed) || errors.Is(err, signaling.ErrTransportUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func relayFailureAllowsFallback(ctx context.Context, err error) bool {
	if err == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	var failure *connectionmanager.Failure
	if errors.As(err, &failure) {
		return failure.AllowsFallback()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func (s *Service) serveDirect(setupCtx, lifetime context.Context, document api.PeerAttemptDescriptor, authority peersession.Authority, local identitystore.PeerEndpoint, localCertificate, peerCertificate endpointidentity.Certificate, fingerprint networkadaptation.Fingerprint, probeOnly bool, claim func() bool, activity *transportActivity) (bool, error) {
	started := time.Now()
	timing := map[string]int64{}
	mark := func(name string) { timing[name] = time.Since(started).Milliseconds() }
	defer func() {
		diagnosticlog.TryInfo("peer direct transport timing", "side", "host", "intent_id", document.IntentID, "attempt_generation", document.AttemptGeneration, "network_generation", document.NetworkGeneration, "milestones_ms", timing, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	ownerCtx, cancelOwner := context.WithCancel(lifetime)
	directCtx, cancelDeadline, err := directSetupContext(setupCtx, document.ExpiresAt)
	if err != nil {
		cancelOwner()
		return false, err
	}
	owner := &directAttempt{cancel: cancelOwner}
	stopOwnerCancellation := context.AfterFunc(ownerCtx, cancelDeadline)
	s.directMu.Lock()
	s.directAttempts[owner] = struct{}{}
	s.directMu.Unlock()
	defer func() {
		stopOwnerCancellation()
		cancelDeadline()
		cancelOwner()
		s.directMu.Lock()
		delete(s.directAttempts, owner)
		s.directMu.Unlock()
	}()
	descriptor := controlledAttemptDescriptor(document, local.RootPublicKey)
	pmtuKey := authority.PMTUKey()
	mappingSource := s.config.SocketMapping
	class := peerquic.ClassInteractive
	pathSuffix := "interactive"
	if document.Purpose == "private_preview" {
		class = peerquic.ClassPreview
		pathSuffix = "preview"
	}
	if document.Purpose == "direct_probe" {
		mappingSource = nil
	}
	factory, err := directpath.NewSignalingFactory(directpath.SignalingFactoryConfig{Descriptors: directpath.DescriptorSourceFunc(func(context.Context, directpath.Generation) (directpath.AttemptDescriptor, error) {
		return descriptor, nil
	}), SocketMapping: mappingSource, Lifetime: ownerCtx, TLS: s.config.TLS.Clone(), Dial: func(dialCtx context.Context, config signaling.WebSocketConfig) (directpath.SignalingTransport, error) {
		return s.config.SignalingSubstrate.Open(dialCtx, config)
	}, Assembly: directpath.Config{Sockets: udpsocket.DevelopmentConfig(true, true), PMTUKey: pmtuKey[:], MaximumPMTU: networkadaptation.DevelopmentPMTUPolicy().MaximumPayload, ApplicationQueue: 64, PMTUResponseLimit: time.Second}})
	if err != nil {
		return false, err
	}
	assembly, err := factory.Create(directCtx, directpath.Generation{Attempt: document.AttemptGeneration, Network: document.NetworkGeneration})
	if err != nil {
		return false, err
	}
	mark("ice_ready")
	now := s.config.Clock().UTC()
	localLeaf, err := endpointidentity.NewTLSCertificate(localCertificate, local.RootPublicKey, local.QUICPrivateKey, now, document.ExpiresAt.Sub(now))
	if err != nil {
		return false, errors.Join(err, assembly.Close())
	}
	mark("local_certificate_ready")
	peerRaw, err := peerCertificate.MarshalBinary()
	if err != nil {
		return false, errors.Join(err, assembly.Close())
	}
	serverTLS, err := endpointidentity.ServerTLS(localLeaf, endpointidentity.PeerExpectation{RootPublic: local.RootPublicKey, Certificate: peerRaw, Expected: endpointidentity.Expected{AccountID: document.AccountID, Role: endpointidentity.RoleCLI, EndpointID: document.InitiatorEndpointID, Generation: peerCertificate.Claims.Generation}}, peerquic.ALPN, s.config.Clock)
	if err != nil {
		return false, errors.Join(err, assembly.Close())
	}
	mark("tls_config_ready")
	var listener *peerquic.Listener
	if document.Purpose == "direct_probe" {
		listener, err = assembly.ListenProbeQUIC(directCtx, serverTLS, document.ExpiresAt.Sub(now))
	} else {
		listener, err = assembly.ListenQUIC(directCtx, serverTLS, peerquic.DevelopmentSessionConfig(class), directpath.PMTUConfig{Policy: networkadaptation.DevelopmentPMTUPolicy(), Cache: s.pmtu, Key: networkadaptation.PMTUKey{Fingerprint: fingerprint, PathID: document.IntentID + ":" + pathSuffix, NetworkGeneration: document.NetworkGeneration}, Lifetime: &directpath.LifetimeConfig{Cache: s.lifetime, Fingerprint: fingerprint, Now: s.config.Clock}})
	}
	if err != nil {
		return false, errors.Join(err, assembly.Close())
	}
	mark("quic_listening")
	defer listener.Close()
	session, err := listener.Accept(directCtx)
	if err != nil {
		return false, errors.Join(err, listener.Close(), assembly.Close())
	}
	mark("quic_handshake_complete")
	health, err := directpath.NewHealthConnection(assembly, session)
	if err != nil {
		return false, errors.Join(err, session.Close(), assembly.Close())
	}
	defer health.Close()
	var candidateOwner *candidateOwner
	if document.Purpose == "peer_transport" {
		if activity == nil || activity.owner == nil {
			return false, ErrInvalid
		}
		binding, bindingErr := peerquic.CandidateBinding(session.Connection.ConnectionState().TLS, authority.Transport)
		if bindingErr != nil {
			return false, bindingErr
		}
		candidateID, candidateErr := candidatelease.NewID(binding[:], document.IntentID, document.AttemptGeneration, "direct_quic")
		if candidateErr != nil {
			return false, candidateErr
		}
		candidateOwner = activity.owner
		if err := candidateOwner.Configure(candidateID, document.AttemptGeneration); err != nil {
			return false, err
		}
	}
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ownerCtx.Done():
			_ = health.Close()
		case <-watchDone:
		}
	}()
	routerConfig := peerquic.DevelopmentStreamRouterConfig()
	if document.Purpose == "peer_transport" {
		routerConfig.CandidateControl = func(controlCtx context.Context, stream *quic.Stream) error {
			for {
				message, err := candidatelease.FrameReader(stream)
				if err != nil {
					return err
				}
				ackMessage, err := candidateOwner.Handle(message)
				if err != nil {
					return err
				}
				ack, err := candidatelease.Frame(ackMessage)
				if err == nil {
					_, err = stream.Write(ack)
				}
				if err != nil || message.Type == candidatelease.Release {
					return err
				}
			}
		}
	}
	router, err := peerquic.NewStreamRouter(session, routerConfig)
	if err != nil {
		return false, err
	}
	defer router.Close()
	if err := health.AdmitInitialHealthResponse(directCtx, router); err != nil {
		return false, err
	}
	mark("initial_health_complete")
	if document.Purpose == "peer_transport" {
		if s.config.AuthorizeStream == nil || s.config.ServeStream == nil || document.StreamPolicy == nil {
			return false, ErrInvalid
		}
		if !claim() {
			return false, context.Canceled
		}
		if err := retainDirectCandidate(directCtx, cancelDeadline, candidateOwner); err != nil {
			return false, err
		}
		return true, s.serveDirectTransport(ownerCtx, document, authority, session, router, activity)
	}
	cancelDeadline()
	if document.Purpose == "health_probe" {
		if err := router.WaitHealthExchanges(ownerCtx, 2); err != nil {
			return false, err
		}
		if !claim() {
			return false, context.Canceled
		}
		// The second exchange's completion frame is the initiator's success
		// boundary. Keep the session alive until the initiator consumes it and
		// closes normally; bound the drain so an abandoned probe cannot retain
		// host resources.
		drain := time.NewTimer(time.Second)
		defer drain.Stop()
		select {
		case <-session.Connection.Context().Done():
		case <-drain.C:
		}
		return true, nil
	}
	if probeOnly {
		idle, waitErr := router.WaitLifetimeProbe(setupCtx)
		if waitErr != nil {
			return false, waitErr
		}
		if err := s.lifetime.RecordSuccess(fingerprint, idle, s.config.Clock().UTC()); err != nil {
			return false, err
		}
		if !claim() {
			return false, context.Canceled
		}
		return true, nil
	}
	binding, err := peerquic.ExporterBinding(session.Connection.ConnectionState().TLS, authority.Context)
	if err != nil {
		return false, err
	}
	if authority.Context.Consumer == "file_transfer_key" {
		stream, acceptErr := router.Accept(ownerCtx)
		if acceptErr != nil {
			return false, acceptErr
		}
		connection, bindErr := newBoundResponderConn(ownerCtx, stream, binding, authority.LocalEndpointID(), authority.PeerEndpointID())
		if bindErr != nil {
			_ = stream.Close()
			return false, bindErr
		}
		if !claim() {
			_ = connection.Close()
			return false, context.Canceled
		}
		receiveErr := s.exchangeTransferKey(connection, document, authority)
		closeErr := connection.Close()
		if receiveErr != nil || closeErr != nil || s.config.ServeTransfer == nil {
			return true, errors.Join(receiveErr, closeErr)
		}
		for {
			stream, acceptErr := router.Accept(ownerCtx)
			if acceptErr != nil {
				if ownerCtx.Err() != nil || lifetime.Err() != nil {
					return true, lifetime.Err()
				}
				return true, acceptErr
			}
			connection, bindErr := newBoundResponderConn(ownerCtx, stream, binding, authority.LocalEndpointID(), authority.PeerEndpointID())
			if bindErr != nil {
				_ = stream.Close()
				return true, bindErr
			}
			go func(conn net.Conn) {
				if err := s.config.ServeTransfer(ownerCtx, conn); err != nil && s.config.ObserveError != nil {
					s.config.ObserveError(err)
				}
				_ = conn.Close()
			}(connection)
		}
	}
	if authority.Context.Consumer == "private_preview" {
		if s.config.ServePreview == nil {
			return false, ErrInvalid
		}
		if !claim() {
			return false, context.Canceled
		}
		if err := router.Handoff(); err != nil {
			return true, err
		}
		server := &http3.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			port, parseErr := strconv.ParseUint(request.Header.Get("X-Paperboat-Preview-Port"), 10, 16)
			if request.Method != http.MethodConnect || request.Proto != peerpreview.HTTP3ConnectProtocol || request.Host != "private-preview.paperboat" || request.URL.Path != "/" || parseErr != nil || port == 0 {
				diagnosticlog.TryInfo("private preview HTTP/3 CONNECT rejected", "method", request.Method, "protocol", request.Proto, "host", request.Host, "path", request.URL.Path, "port", request.Header.Get("X-Paperboat-Preview-Port"), "port_error", parseErr)
				http.Error(writer, "invalid private preview request", http.StatusBadRequest)
				return
			}
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			go func() {
				if serveErr := s.config.ServePreview(request.Context(), remote); serveErr != nil && request.Context().Err() == nil {
					diagnosticlog.TryInfo("private preview target bridge failed", "port", port, "error", serveErr)
				}
			}()
			if openErr := peerpreview.Open(request.Context(), local, uint16(port)); openErr != nil {
				http.Error(writer, "private preview target unavailable", http.StatusBadGateway)
				return
			}
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			type copyResult struct {
				direction string
				bytes     int64
				err       error
			}
			copyDone := make(chan copyResult, 2)
			go func() {
				count, err := io.Copy(local, request.Body)
				copyDone <- copyResult{direction: "client_to_target", bytes: count, err: err}
			}()
			go func() {
				count, err := io.Copy(flushingPreviewWriter{writer: writer}, local)
				copyDone <- copyResult{direction: "target_to_client", bytes: count, err: err}
			}()
			first, second := <-copyDone, <-copyDone
			diagnosticlog.TryInfo("private preview HTTP/3 CONNECT closed", "port", port, "first_direction", first.direction, "first_bytes", first.bytes, "first_error", first.err, "second_direction", second.direction, "second_bytes", second.bytes, "second_error", second.err, "request_error", request.Context().Err())
		})}
		defer server.Close()
		return true, server.ServeQUICConn(session.Connection)
	}
	if authority.Context.Consumer == "codex" {
		stream, acceptErr := router.Accept(ownerCtx)
		if acceptErr != nil {
			return false, acceptErr
		}
		connection, bindErr := newBoundResponderConn(ownerCtx, stream, binding, authority.LocalEndpointID(), authority.PeerEndpointID())
		if bindErr != nil {
			_ = stream.Close()
			return false, bindErr
		}
		defer connection.Close()
		if s.config.ServeCodex == nil {
			return false, ErrInvalid
		}
		if !claim() {
			return false, context.Canceled
		}
		return true, s.config.ServeCodex(ownerCtx, connection)
	}
	if authority.Context.Consumer == "ssh" {
		stream, acceptErr := router.Accept(ownerCtx)
		if acceptErr != nil {
			return false, acceptErr
		}
		connection, bindErr := newBoundResponderConn(ownerCtx, stream, binding, authority.LocalEndpointID(), authority.PeerEndpointID())
		if bindErr != nil {
			_ = stream.Close()
			return false, bindErr
		}
		defer connection.Close()
		if s.config.ServeSSH == nil || !claim() {
			return false, ErrInvalid
		}
		return true, s.config.ServeSSH(ownerCtx, connection)
	}
	served := make(chan error, 3)
	for index := range 3 {
		stream, acceptErr := router.Accept(ownerCtx)
		if acceptErr != nil {
			return index > 0, acceptErr
		}
		connection, bindErr := newBoundResponderConn(ownerCtx, stream, binding, authority.LocalEndpointID(), authority.PeerEndpointID())
		if bindErr != nil {
			_ = stream.Close()
			return index > 0, bindErr
		}
		if index == 0 && !claim() {
			_ = connection.Close()
			return false, context.Canceled
		}
		go func(conn net.Conn) { served <- s.config.Serve(conn) }(connection)
	}
	for range 3 {
		select {
		case <-served:
		case <-lifetime.Done():
			return true, lifetime.Err()
		}
	}
	return true, nil
}

type flushingPreviewWriter struct{ writer http.ResponseWriter }

func (w flushingPreviewWriter) Write(value []byte) (int, error) {
	count, err := w.writer.Write(value)
	if err != nil {
		return count, err
	}
	if flusher, ok := w.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return count, nil
}

func directSetupContext(parent context.Context, expiresAt time.Time) (context.Context, context.CancelFunc, error) {
	if parent == nil || expiresAt.IsZero() {
		return nil, nil, ErrInvalid
	}
	if deadline, ok := parent.Deadline(); ok && !expiresAt.Before(deadline) {
		ctx, cancel := context.WithCancel(parent)
		return ctx, cancel, nil
	}
	ctx, cancel := context.WithDeadline(parent, expiresAt)
	return ctx, cancel, nil
}

func retainDirectCandidate(setup context.Context, cancelSetup context.CancelFunc, owner *candidateOwner) error {
	if setup == nil || cancelSetup == nil || owner == nil {
		return ErrInvalid
	}
	if err := owner.WaitRetained(setup); err != nil {
		return err
	}
	cancelSetup()
	return nil
}

func (s *Service) serveDirectTransport(ctx context.Context, document api.PeerAttemptDescriptor, authority peersession.Authority, session *peerquic.Session, router *peerquic.StreamRouter, activity *transportActivity) error {
	if ctx == nil || session == nil || session.Connection == nil || router == nil {
		return ErrInvalid
	}
	// The host attempt lifetime is controlled by descriptor polling, but the
	// authenticated QUIC session is also an immediate close boundary. Tie the
	// stream accept loop to both so a client-side final-lease close cannot leave
	// a carrier parked until ICE/descriptor expiry.
	transportCtx, cancel := context.WithCancel(ctx)
	go func() {
		if activity != nil && activity.owner != nil {
			select {
			case <-session.Connection.Context().Done():
				cancel()
			case <-activity.owner.Released():
				cancel()
			case <-transportCtx.Done():
			}
			return
		}
		select {
		case <-session.Connection.Context().Done():
			cancel()
		case <-transportCtx.Done():
		}
	}()
	if document.Purpose != "peer_transport" {
		var deadlineCancel context.CancelFunc
		transportCtx, deadlineCancel = context.WithDeadline(transportCtx, document.ExpiresAt)
		cancel = func() {
			deadlineCancel()
		}
	}
	defer cancel()
	permits := make(chan struct{}, document.StreamPolicy.MaximumStreams)
	var streams sync.WaitGroup
	defer streams.Wait()
	for {
		stream, err := router.Accept(transportCtx)
		if err != nil {
			if transportCtx.Err() != nil {
				return transportCtx.Err()
			}
			return err
		}
		select {
		case permits <- struct{}{}:
		case <-transportCtx.Done():
			_ = stream.Close()
			return transportCtx.Err()
		default:
			_ = stream.Close()
			continue
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			defer func() { <-permits }()
			header, connection, bindErr := newAuthorizedResponderConn(transportCtx, stream, session, authority, document.StreamPolicy.AllowedConsumers)
			if bindErr != nil {
				_ = stream.Close()
				return
			}
			boundAuthorizer := func(authorizeCtx context.Context, value streamauth.Header) (server.Authorization, error) {
				return s.authorizeStream(authorizeCtx, document, value)
			}
			if header.Resumable {
				_, resumeErr := boundAuthorizer(transportCtx, header)
				if resumeErr == nil {
					resumeErr = s.streams.Attach(authority.PeerEndpointID(), header, connection, s.config.ServeStream, activity)
				}
				if resumeErr != nil && s.config.ObserveError != nil {
					s.config.ObserveError(resumeErr)
				}
				return
			}
			if activity != nil {
				activity.Open()
				defer activity.Close()
			}
			if err := DispatchParsedStream(transportCtx, header, connection, boundAuthorizer, s.config.ServeStream); err != nil && s.config.ObserveError != nil {
				s.config.ObserveError(err)
			}
		}()
	}
}

func newAuthorizedResponderConn(ctx context.Context, stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}, session *peerquic.Session, authority peersession.Authority, allowed []string) (streamauth.Header, *boundResponderConn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return streamauth.Header{}, nil, err
		}
	}
	var header streamauth.Header
	payload, err := peerquic.ReadFirstRecordAuthorized(stream, func(encoded []byte) ([32]byte, error) {
		parsed, parseErr := streamauth.Parse(encoded, time.Now().UTC())
		if parseErr != nil || !slices.Contains(allowed, parsed.Consumer) {
			return [32]byte{}, ErrStreamDispatch
		}
		streamAuthority, authorityErr := authority.ResponderStream(parsed.Grant())
		if authorityErr != nil {
			return [32]byte{}, authorityErr
		}
		header = parsed
		return peerquic.ExporterBindingForStream(session.Connection.ConnectionState().TLS, streamAuthority.Transport, streamAuthority.Stream)
	})
	clearErr := stream.SetDeadline(time.Time{})
	if err != nil || clearErr != nil || len(payload) == 0 {
		return streamauth.Header{}, nil, errors.Join(err, clearErr)
	}
	return header, &boundResponderConn{stream: stream, reader: bytes.NewReader(nil), local: peerAddr(authority.LocalEndpointID()), remote: peerAddr(authority.PeerEndpointID())}, nil
}

func controlledAttemptDescriptor(value api.PeerAttemptDescriptor, root ed25519.PublicKey) directpath.AttemptDescriptor {
	return directpath.AttemptDescriptor{Document: value, IntentID: value.IntentID, AttemptGeneration: value.AttemptGeneration, NetworkGeneration: value.NetworkGeneration, Role: signaling.RoleControlled, InitiatorEndpointID: value.InitiatorEndpointID, ResponderEndpointID: value.ResponderEndpointID, RootPublicKey: append(ed25519.PublicKey(nil), root...), SignalingURL: value.Signaling.URL, SignalingCredential: value.Signaling.Credential, RelayRegion: value.Relays[0].Region, RelayQUICURL: value.Relays[0].QUICURL, RelayWSSURL: value.Relays[0].WSSURL, RelayCredential: value.Relays[0].RouteToken, RelayPMTUCredential: value.Relays[0].PMTUToken, RelayPMTUURL: value.Relays[0].PMTUURL, RouteGeneration: value.Relays[0].RouteGeneration, STUNURLs: append([]string(nil), value.Direct.STUNURLs...), LocalUfrag: value.Direct.ICEUfrag, LocalPassword: value.Direct.ICEPassword, IssuedAt: value.IssuedAt, ExpiresAt: value.ExpiresAt}
}

type boundResponderConn struct {
	stream io.ReadWriteCloser
	reader *bytes.Reader
	local  net.Addr
	remote net.Addr
}

func newBoundResponderConn(ctx context.Context, stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}, binding [32]byte, localID, remoteID string) (*boundResponderConn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	payload, err := peerquic.ReadFirstRecord(stream, binding)
	clearErr := stream.SetDeadline(time.Time{})
	if err != nil || clearErr != nil {
		return nil, errors.Join(err, clearErr)
	}
	return &boundResponderConn{stream: stream, reader: bytes.NewReader(payload), local: peerAddr(localID), remote: peerAddr(remoteID)}, nil
}

func (c *boundResponderConn) Read(target []byte) (int, error) {
	if c.reader.Len() > 0 {
		return c.reader.Read(target)
	}
	return c.stream.Read(target)
}
func (c *boundResponderConn) Write(payload []byte) (int, error) { return c.stream.Write(payload) }
func (c *boundResponderConn) Close() error                      { return c.stream.Close() }
func (c *boundResponderConn) CloseWrite() error {
	if closer, ok := c.stream.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.stream.Close()
}
func (c *boundResponderConn) LocalAddr() net.Addr  { return c.local }
func (c *boundResponderConn) RemoteAddr() net.Addr { return c.remote }
func (c *boundResponderConn) SetDeadline(value time.Time) error {
	return c.stream.(interface{ SetDeadline(time.Time) error }).SetDeadline(value)
}
func (c *boundResponderConn) SetReadDeadline(value time.Time) error {
	return c.stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(value)
}
func (c *boundResponderConn) SetWriteDeadline(value time.Time) error {
	return c.stream.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline(value)
}

type peerAddr string

func (peerAddr) Network() string  { return "paperboat-peer-quic" }
func (a peerAddr) String() string { return string(a) }
