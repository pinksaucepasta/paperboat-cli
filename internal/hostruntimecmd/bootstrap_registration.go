package hostruntimecmd

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/inbox"
)

// saveBootstrapRegistration establishes the local machine identity before a
// service is installed. A fresh `pb pair` must therefore be restartable and
// must not depend on a prior interactive `pb setup` call.
func saveBootstrapRegistration(store *identity.Store, serverURL string, material bootstrap.Material, sshUser string, sshPort uint16) error {
	inboxPath, err := inbox.DefaultPath()
	if err != nil {
		return err
	}
	if err := inbox.EnsurePath(inboxPath); err != nil {
		return err
	}
	key := store.Current()
	sshUser, sshPort = bootstrapSSHFields(material.SetupMode, sshUser, sshPort)
	return store.SaveRegistration(identity.Registration{
		ServerURL:              strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		MachineID:              material.UserMachineID,
		EnvironmentID:          material.EnvironmentID,
		PublicKeyID:            key.ID,
		PublicIdentityKey:      base64.RawURLEncoding.EncodeToString(key.Public()),
		InboxPath:              inboxPath,
		InstallationGeneration: material.InstallationGeneration,
		SetupMode:              material.SetupMode,
		SetupRoles:             append([]string(nil), material.SetupRoles...),
		SSHUser:                strings.TrimSpace(sshUser),
		SSHPort:                sshPort,
		UpdatedAt:              time.Now().UTC(),
	})
}

func bootstrapSSHFields(setupMode, sshUser string, sshPort uint16) (string, uint16) {
	if setupMode != "host" {
		return "", 0
	}
	return strings.TrimSpace(sshUser), sshPort
}

func unixBootstrapSSHFields(setupMode, username string) (string, uint16) {
	if setupMode != "host" {
		return "", 0
	}
	return bootstrapSSHFields(setupMode, username, 22)
}
