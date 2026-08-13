package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type TransferKeyDeliverer interface {
	DeliverTransferKey(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, error)
}

type directTransferKeyDeliverer interface {
	PrepareTransferKey(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, http.RoundTripper, error)
}

type TransferKeyReceiver interface {
	ReceiveTransferKey(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, *transfercrypto.KeyVault) (peercontext.Context, error)
}

type directTransferKeyReceiver interface {
	PrepareReceiveTransferKey(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, *transfercrypto.KeyVault) (peercontext.Context, http.RoundTripper, error)
}

func KeyOperationID(transferID string) string {
	digest := sha256.Sum256([]byte("paperboat-file-transfer-key-v1\x00" + transferID))
	return "ft_key_" + hex.EncodeToString(digest[:16])
}

type PreparedKey struct {
	Material transfercrypto.KeyMaterial
	Context  peercontext.Context
	Direct   http.RoundTripper
}

func (k *PreparedKey) Close() error {
	if k == nil || k.Direct == nil {
		return nil
	}
	var err error
	if closer, ok := k.Direct.(io.Closer); ok {
		err = closer.Close()
	} else if closer, ok := k.Direct.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	k.Direct = nil
	return err
}

type KeyCoordinator struct {
	vault    *transfercrypto.KeyVault
	deliver  TransferKeyDeliverer
	generate func() (transfercrypto.KeyMaterial, error)
}

func NewKeyCoordinator(vault *transfercrypto.KeyVault, deliverer TransferKeyDeliverer) (*KeyCoordinator, error) {
	if vault == nil || deliverer == nil {
		return nil, errors.New("file transfer key coordinator requires a vault and peer deliverer")
	}
	return &KeyCoordinator{vault: vault, deliver: deliverer, generate: transfercrypto.GenerateKeyMaterial}, nil
}

func (c *KeyCoordinator) Prepare(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding) (PreparedKey, error) {
	if c == nil || ctx == nil || c.vault == nil || c.deliver == nil {
		return PreparedKey{}, errors.New("file transfer key coordinator is unavailable")
	}
	material, err := c.vault.Load(binding.TransferID, binding.Generation)
	if err != nil {
		if !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
			return PreparedKey{}, err
		}
		material, err = c.generate()
		if err != nil {
			return PreparedKey{}, err
		}
		if err := c.vault.Save(binding.TransferID, binding.Generation, material, binding.ExpiresAt); err != nil {
			material.Destroy()
			return PreparedKey{}, err
		}
	}
	var peerContext peercontext.Context
	var direct http.RoundTripper
	if preparer, ok := c.deliver.(directTransferKeyDeliverer); ok {
		peerContext, direct, err = preparer.PrepareTransferKey(ctx, target, binding, material)
	} else {
		peerContext, err = c.deliver.DeliverTransferKey(ctx, target, binding, material)
	}
	if err != nil {
		material.Destroy()
		return PreparedKey{}, err
	}
	if err := c.vault.SaveLocalBound(binding.TransferID, binding.Generation, material, binding.ExpiresAt, peerContext); err != nil {
		if closer, ok := direct.(io.Closer); ok {
			_ = closer.Close()
		}
		material.Destroy()
		return PreparedKey{}, err
	}
	return PreparedKey{Material: material, Context: peerContext, Direct: direct}, nil
}

func (c *KeyCoordinator) Receive(ctx context.Context, target resolver.ConnectInfo, binding transfercrypto.KeyControlBinding) (PreparedKey, error) {
	if c == nil || ctx == nil || c.vault == nil || c.deliver == nil {
		return PreparedKey{}, errors.New("file transfer key coordinator is unavailable")
	}
	if material, peer, err := c.vault.LoadBound(binding.TransferID, binding.Generation); err == nil {
		return PreparedKey{Material: material, Context: peer}, nil
	} else if !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		return PreparedKey{}, err
	}
	receiver, ok := c.deliver.(TransferKeyReceiver)
	if !ok {
		return PreparedKey{}, errors.New("file transfer key receiver is unavailable")
	}
	var peer peercontext.Context
	var direct http.RoundTripper
	var err error
	if preparer, ok := c.deliver.(directTransferKeyReceiver); ok {
		peer, direct, err = preparer.PrepareReceiveTransferKey(ctx, target, binding, c.vault)
	} else {
		peer, err = receiver.ReceiveTransferKey(ctx, target, binding, c.vault)
	}
	if err != nil {
		return PreparedKey{}, err
	}
	material, storedPeer, err := c.vault.LoadBound(binding.TransferID, binding.Generation)
	if err != nil || storedPeer != peer {
		if closer, ok := direct.(io.Closer); ok {
			_ = closer.Close()
		}
		material.Destroy()
		return PreparedKey{}, errors.Join(errors.New("received file transfer key binding is invalid"), err)
	}
	return PreparedKey{Material: material, Context: peer, Direct: direct}, nil
}

func (c *KeyCoordinator) Erase(transferID string) error {
	if c == nil || c.vault == nil {
		return errors.New("file transfer key coordinator is unavailable")
	}
	return c.vault.Delete(transferID)
}
