package wsapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// The welcome frame advertises what this build answers, and it has now drifted
// twice.
//
// The first time, eight frames were missing — every one phases 4 to 6 added —
// and a client branching on the list would have concluded that attachments,
// contacts and disappearing timers were unavailable on a server that had served
// all three for months. It was fixed by hand, with a comment asking the next
// person to remember. The next person did not: message.poll.vote and
// device.stop were dispatched and unannounced.
//
// So the list stops being maintained by memory. This walks the dispatch switch
// in the source and fails on anything it answers without saying so. It reads
// the AST rather than grepping because a `case` inside a nested switch, or a
// constant renamed but not moved, would slip past a regular expression — and
// slipping past is the entire failure mode.
//
// The exemptions are the frames a client cannot usefully branch on: hello is
// how the connection opens, and ping is answered by everything that speaks the
// protocol at all.
var notAdvertised = []string{"hello", "ping"}

// And two entries name no frame. They are the two values of PairRequest.Method,
// and a client does have to know which this build supports — asking for code
// pairing on a server that only does QR fails after a round trip. The list is
// capabilities, not a frame index, and these are the only two places the
// difference shows.
var notFrames = []string{"pair.qr", "pair.code"}

func TestEveryDispatchedFrameIsAnnounced(t *testing.T) {
	dispatched := dispatchedFrames(t)
	if len(dispatched) < 30 {
		t.Fatalf("found %d dispatched frames; the switch was not parsed properly "+
			"and this test is now asserting nothing", len(dispatched))
	}

	for _, frame := range dispatched {
		if slices.Contains(notAdvertised, frame) || slices.Contains(features, frame) {
			continue
		}
		t.Errorf("%q is dispatched but not in features. A client branching on the "+
			"welcome frame will not use it, on a server that serves it.", frame)
	}
}

func TestNothingAnnouncedIsUnimplemented(t *testing.T) {
	// The opposite drift, and the worse one: a client is told a capability
	// exists, uses it, and gets "unknown frame type" — which reads as a bug in
	// the client.
	dispatched := dispatchedFrames(t)
	for _, frame := range features {
		if slices.Contains(notFrames, frame) {
			continue
		}
		if !slices.Contains(dispatched, frame) {
			t.Errorf("%q is announced but nothing dispatches it", frame)
		}
	}
}

// dispatchedFrames returns the frame values the session switch answers.
//
// It resolves each `case TypeX` back to the string constant, so the test is
// comparing what goes on the wire rather than the identifiers used to spell it.
func dispatchedFrames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	//nolint:staticcheck // This contract test intentionally scans all source files, independent of build tags.
	pkg, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	values := map[string]string{}
	var cases []string
	for _, p := range pkg {
		for _, file := range p.Files {
			collectConstants(file, values)
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "dispatch" {
					return true
				}
				ast.Inspect(fn.Body, func(inner ast.Node) bool {
					clause, ok := inner.(*ast.CaseClause)
					if !ok {
						return true
					}
					for _, expr := range clause.List {
						if id, ok := expr.(*ast.Ident); ok {
							cases = append(cases, id.Name)
						}
					}
					return true
				})
				return false
			})
		}
	}

	out := make([]string, 0, len(cases))
	for _, name := range cases {
		value, ok := values[name]
		if !ok {
			t.Errorf("case %s is not a string constant in this package; the test "+
				"cannot tell what it puts on the wire", name)
			continue
		}
		out = append(out, value)
	}
	return out
}

func collectConstants(file *ast.File, into map[string]string) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				into[name.Name] = strings.Trim(lit.Value, `"`)
			}
		}
	}
}
