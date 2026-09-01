package preview

import "context"

type controlProof func(context.Context, string, string, string, []byte) ([]byte, error)

func (proof controlProof) Proof(ctx context.Context, operationID, method, path string, body []byte) ([]byte, error) {
	return proof(ctx, operationID, method, path, body)
}
