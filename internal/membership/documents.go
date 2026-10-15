package membership

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// DocOf is the store's form of a document the kit validated (an answer's
// or a feed page's): its members parsed, and the document itself as JSON,
// as received (the plan's DB20). It holds no email and no person's name:
// the document has none (README 6.2).
func DocOf(d kc.AccountDoc) (store.ContractDoc, error) {
	sub, err := uuid.Parse(d.Sub)
	if err != nil {
		return store.ContractDoc{}, fmt.Errorf("%w: the document's sub", kc.ErrUnverified)
	}
	gen, err := uuid.Parse(d.Generation)
	if err != nil {
		return store.ContractDoc{}, fmt.Errorf("%w: the document's generation", kc.ErrUnverified)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return store.ContractDoc{}, err
	}
	out := store.ContractDoc{
		Sub: sub, Generation: gen, Version: d.Version, Status: d.Status,
		DisabledAt: timeOf(d.DisabledAt), SessionsRevokedAt: timeOf(d.SessionsRevokedAt), CredentialsRevokedAt: timeOf(d.CredentialsRevokedAt),
		Raw: raw,
	}
	for _, w := range d.Workspaces {
		id, err := uuid.Parse(w.ID)
		if err != nil {
			return store.ContractDoc{}, fmt.Errorf("%w: a workspace's id", kc.ErrUnverified)
		}
		out.Workspaces = append(out.Workspaces, store.ContractDocWorkspace{ID: id, Kind: w.Kind, Role: w.Role, Status: w.Status, WVersion: w.WVersion})
	}
	return out, nil
}

func timeOf(t *kc.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.Time
	return &v
}
