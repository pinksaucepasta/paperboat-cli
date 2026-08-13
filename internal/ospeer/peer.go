//go:build linux || darwin

package ospeer

import (
	"errors"
	"net"
	"os/user"
	"strconv"

	"github.com/tailscale/peercred"
)

var ErrUnverified = errors.New("Unix peer credentials are incomplete or unsupported")

type Identity struct {
	UID int
	GID int
	PID int
}

func Get(connection net.Conn) (Identity, error) {
	credentials, err := peercred.Get(connection)
	if err != nil {
		return Identity{}, errors.Join(ErrUnverified, err)
	}
	uidText, uidOK := credentials.UserID()
	pid, pidOK := credentials.PID()
	uid, uidErr := strconv.Atoi(uidText)
	if !uidOK || !pidOK || uidErr != nil || uid < 0 || pid <= 0 {
		return Identity{}, ErrUnverified
	}
	account, err := user.LookupId(uidText)
	if err != nil {
		return Identity{}, errors.Join(ErrUnverified, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid < 0 {
		return Identity{}, ErrUnverified
	}
	return Identity{UID: uid, GID: gid, PID: pid}, nil
}
