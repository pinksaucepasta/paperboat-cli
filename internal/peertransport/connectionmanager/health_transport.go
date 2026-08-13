package connectionmanager

import (
	"context"
	"errors"
)

type ActiveHealthCapability struct {
	Path      Path
	Transport ActiveHealthTransport
}

// ActiveHealthConnection keeps carrier-specific authentication state with the
// selected connection that established it.
type ActiveHealthConnection interface {
	Connection
	ActiveHealthCapability() (ActiveHealthCapability, error)
}

// InitialHealthConnection starts ready and becomes trusted only after one
// authenticated health exchange succeeds on the established path.
type InitialHealthConnection interface {
	ActiveHealthConnection
	AdmitInitialHealth(context.Context, [16]byte) error
}

// ConnectionHealthTransport obtains the authenticated health capability owned
// by a selected connection without exposing carrier-specific credentials to the
// pool.
func ConnectionHealthTransport(selection Selection) (ActiveHealthTransport, error) {
	if selection.Generation == 0 || !validPath(selection.Path) || nilConnection(selection.Connection) || selection.Connection.State() != StateTrusted {
		return nil, errors.New("invalid selected connection health transport")
	}
	connection, ok := selection.Connection.(ActiveHealthConnection)
	if !ok {
		return nil, errors.New("selected connection has no active health capability")
	}
	capability, err := connection.ActiveHealthCapability()
	if err != nil {
		return nil, err
	}
	if capability.Path != selection.Path {
		return nil, errors.New("selected connection health capability path mismatch")
	}
	if capability.Transport == nil {
		return nil, errors.New("selected connection returned no active health capability")
	}
	return capability.Transport, nil
}

func validPath(path Path) bool {
	return path == PathDirectQUIC || path == PathRelayQUIC || path == PathWSS
}
