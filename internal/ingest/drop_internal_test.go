package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

// TestADroppedPipelineSealsNothing: once the router lets go of a pipeline
// (a notice, or a failed seal), a caller that still holds it cannot seal
// with it. It would seal under a content key a reset may have deleted
// (DS49). A pipeline the router keeps still seals as before.
func TestADroppedPipelineSealsNothing(t *testing.T) {
	tenant, other := uuid.New(), uuid.New()
	for _, c := range []struct {
		name string
		drop func(r *Router, device uuid.UUID, p *Pipeline)
		gone bool
	}{
		{"forget", func(r *Router, device uuid.UUID, _ *Pipeline) { r.Forget(device) }, true},
		{"forget the workspace", func(r *Router, _ uuid.UUID, _ *Pipeline) { r.ForgetWorkspace(tenant) }, true},
		{"forget all", func(r *Router, _ uuid.UUID, _ *Pipeline) { r.ForgetAll() }, true},
		{"a failed seal", func(r *Router, device uuid.UUID, p *Pipeline) { r.drop(device, p) }, true},
		{"another workspace", func(r *Router, _ uuid.UUID, _ *Pipeline) { r.ForgetWorkspace(other) }, false},
		{"another number", func(r *Router, _ uuid.UUID, _ *Pipeline) { r.Forget(uuid.New()) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			device := uuid.New()
			p := &Pipeline{tenant: tenant}
			r := &Router{pipelines: map[uuid.UUID]*Pipeline{device: p}}
			c.drop(r, device, p)
			_, kept := r.pipelines[device]
			if kept == c.gone {
				t.Fatalf("the router kept the pipeline: %v", kept)
			}
			if got := p.dropped.Load(); got != c.gone {
				t.Fatalf("dropped %v, want %v", got, c.gone)
			}
			if !c.gone {
				return
			}
			_, _, err := p.sealAll(context.Background(), uuid.New(), map[seal.Kind][]byte{seal.KindBody: []byte("oi")})
			if !errors.Is(err, errPipelineDropped) || !staleKey(err) {
				t.Fatalf("a dropped pipeline's seal: %v, want errPipelineDropped", err)
			}
		})
	}
}
