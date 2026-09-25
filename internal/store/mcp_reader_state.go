package store

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MCPReaderStates keeps an attested reader's sealed state: four named blobs
// per reader, each written with a compare-and-swap on its generation.
//
// The blobs are sealed inside the enclave under a KMS key only the attested
// image can use. This server cannot open them and does not try; it stores
// the bytes and hands them back. What it does guarantee is ordering: a write
// names the generation it replaces, and a write against any other generation
// changes nothing, so a second enclave or a replayed old blob shows up as a
// conflict instead of silently winning.
type MCPReaderStates struct{ pool *pgxpool.Pool }

// NewMCPReaderStates returns the reader state store.
func NewMCPReaderStates(pool *pgxpool.Pool) *MCPReaderStates { return &MCPReaderStates{pool: pool} }

// MCPReaderStateNames are the collections a reader keeps. The table's CHECK
// holds the same list.
var MCPReaderStateNames = []string{"as-clients", "as-connections", "as-tokens", "infra"}

var (
	// ErrReaderStateNotFound is a collection that has never been written.
	ErrReaderStateNotFound = errors.New("store: no such reader state")
	// ErrReaderStateConflict is a write against a generation that is not the
	// current one. Put returns the current generation alongside it.
	ErrReaderStateConflict = errors.New("store: reader state generation mismatch")
	// ErrReaderStateName is a collection name outside MCPReaderStateNames.
	ErrReaderStateName = errors.New("store: not a reader state name")
)

// ValidMCPReaderStateName reports whether name is one of the collections.
func ValidMCPReaderStateName(name string) bool { return slices.Contains(MCPReaderStateNames, name) }

// Get returns a collection's current generation and blob.
func (s *MCPReaderStates) Get(ctx context.Context, reader, name string) (generation int64, blob []byte, err error) {
	if !ValidMCPReaderStateName(name) {
		return 0, nil, ErrReaderStateName
	}
	err = s.pool.QueryRow(ctx, `SELECT generation, blob FROM mcp_reader_state WHERE reader_id=$1 AND name=$2`,
		reader, name).Scan(&generation, &blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, ErrReaderStateNotFound
	}
	if err != nil {
		return 0, nil, fmt.Errorf("store: get reader state: %w", err)
	}
	return generation, blob, nil
}

// Put writes a collection as generation ifGeneration+1, provided its current
// generation is ifGeneration; zero means it must not exist yet. It is one
// statement either way, so two writers racing on the same generation cannot
// both succeed. On a mismatch it returns ErrReaderStateConflict with the
// current generation, or zero when there is none.
func (s *MCPReaderStates) Put(ctx context.Context, reader, name string, ifGeneration int64, blob []byte) (int64, error) {
	if !ValidMCPReaderStateName(name) {
		return 0, ErrReaderStateName
	}
	if ifGeneration < 0 {
		return 0, errors.New("store: a reader state generation is never negative")
	}
	var generation int64
	var err error
	if ifGeneration == 0 {
		err = s.pool.QueryRow(ctx, `INSERT INTO mcp_reader_state (reader_id, name, generation, blob)
			VALUES ($1, $2, 1, $3) ON CONFLICT (reader_id, name) DO NOTHING RETURNING generation`,
			reader, name, blob).Scan(&generation)
	} else {
		err = s.pool.QueryRow(ctx, `UPDATE mcp_reader_state SET generation = generation + 1, blob = $4, updated_at = now()
			WHERE reader_id=$1 AND name=$2 AND generation=$3 RETURNING generation`,
			reader, name, ifGeneration, blob).Scan(&generation)
	}
	if err == nil {
		return generation, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("store: put reader state: %w", err)
	}
	// Nothing changed. Read what is there for the caller's report; a
	// concurrent writer may have moved it on again, which only makes the
	// answer more current.
	var current int64
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(max(generation), 0) FROM mcp_reader_state WHERE reader_id=$1 AND name=$2`,
		reader, name).Scan(&current); err != nil {
		return 0, fmt.Errorf("store: put reader state: %w", err)
	}
	return current, ErrReaderStateConflict
}
