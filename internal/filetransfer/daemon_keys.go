package filetransfer

import (
	"context"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

// DaemonKeyDeliverer keeps peer carrier ownership in the local daemon while
// exposing the same key-coordinator contract to the file transfer workflow.
type DaemonKeyDeliverer struct{ Client *localapi.Client }

func (d DaemonKeyDeliverer) DeliverTransferKey(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, error) {
	peer, direct, err := d.PrepareTransferKey(ctx, target, binding, material)
	if closer, ok := direct.(interface{ Close() error }); ok {
		err = errors.Join(err, closer.Close())
	}
	return peer, err
}

func (d DaemonKeyDeliverer) PrepareTransferKey(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, http.RoundTripper, error) {
	if d.Client == nil || target.ProjectID == "" || target.MachineGeneration == 0 || target.Terminal == nil || target.Terminal.EnvironmentID == "" {
		return peercontext.Context{}, nil, errors.New("daemon file transfer target is invalid")
	}
	encodedMaterial, err := material.MarshalBinary()
	if err != nil {
		return peercontext.Context{}, nil, err
	}
	request := localapi.FileTransferKeyRequest{
		Schema: localapi.FileTransferKeySchemaV1, MachineID: target.ProjectID, EnvironmentID: target.Terminal.EnvironmentID,
		MachineGeneration: target.MachineGeneration, Transport: target.Transport, OperationID: binding.OperationID,
		TransferID: binding.TransferID, Generation: binding.Generation, ExpiresAt: binding.ExpiresAt, Material: encodedMaterial,
	}
	lease, err := d.Client.PrepareFileTransfer(ctx, request)
	if err != nil {
		return peercontext.Context{}, nil, err
	}
	peer, err := peercontext.ParseBinary(lease.PeerContext)
	if err != nil {
		_ = lease.Close()
		return peercontext.Context{}, nil, err
	}
	if lease.Handle == "" {
		_ = lease.Close()
		return peer, nil, nil
	}
	return peer, lease, nil
}
