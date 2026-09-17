package restapi_test

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/restapi"
)

var updateOpenAPI = flag.Bool("update-openapi", false, "update embedded OpenAPI wire schemas from Go DTOs")

// The response schemas are derived from the shared Go/WS DTOs, but stored in
// the public document. This test makes a wire change require a reviewed spec
// update, without adding a runtime schema dependency to the server.
func TestOpenAPIWireSchemas(t *testing.T) {
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	defs := map[string]any{}
	for _, value := range []any{restapi.Devices{}, restapi.Chats{}, restapi.Page{}, restapi.Message{}, restapi.History{}, restapi.Keys{}, restapi.Grants{}, restapi.Contacts{}, restapi.ScanPage{}} {
		wireSchema(reflect.TypeOf(value), defs)
	}
	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	if *updateOpenAPI {
		for name, schema := range defs {
			schemas[name] = schema
		}
		encoded, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("openapi.json", append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	for name, schema := range defs {
		want, _ := json.Marshal(schema)
		got, _ := json.Marshal(schemas[name])
		if string(want) != string(got) {
			t.Errorf("OpenAPI %s no longer matches the wire DTO; review and regenerate with go test ./internal/restapi -run TestOpenAPIWireSchemas -args -update-openapi", name)
		}
	}
}

func wireSchema(typ reflect.Type, defs map[string]any) map[string]any {
	if typ.Kind() == reflect.Pointer {
		return wireSchema(typ.Elem(), defs) // Every nullable field in these DTOs is omitted when nil.
	}
	if typ == reflect.TypeFor[time.Time]() {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch typ.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": wireSchema(typ.Elem(), defs)}
	case reflect.Struct:
		name := typ.Name()
		if typ.PkgPath() == "whatserver2/internal/restapi" {
			name += "Response"
		}
		ref := map[string]any{"$ref": "#/components/schemas/" + name}
		if _, exists := defs[name]; exists {
			return ref
		}
		properties := map[string]any{}
		required := []string{}
		var fields func(reflect.Type)
		fields = func(value reflect.Type) {
			for i := range value.NumField() {
				field := value.Field(i)
				if field.Anonymous {
					fields(field.Type)
					continue
				}
				tag := strings.Split(field.Tag.Get("json"), ",")
				if tag[0] == "-" || !field.IsExported() {
					continue
				}
				properties[tag[0]] = wireSchema(field.Type, defs)
				if !slices.Contains(tag[1:], "omitempty") {
					required = append(required, tag[0])
				}
			}
		}
		fields(typ)
		slices.Sort(required)
		defs[name] = map[string]any{"type": "object", "properties": properties, "required": required}
		return ref
	default:
		panic("unsupported wire schema type " + typ.String())
	}
}

func TestOpenAPIPublicAndMountedPaths(t *testing.T) {
	mux := http.NewServeMux()
	(&restapi.Handler{}).Mount(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil))
	var doc struct {
		Version  string                     `json:"openapi"`
		Security []map[string][]string      `json:"security"`
		Paths    map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || w.Code != 200 || doc.Version != "3.1.1" || len(doc.Security) != 1 {
		t.Fatalf("invalid public specification: %v %s", err, w.Body.String())
	}
	if len(doc.Paths) != 10 {
		t.Fatalf("unexpected endpoint count: %d", len(doc.Paths))
	}
	for path := range doc.Paths {
		path = strings.ReplaceAll(path, "{device}", "00000000-0000-0000-0000-000000000001")
		path = strings.ReplaceAll(path, "{uid}", "00000000-0000-0000-0000-000000000002")
		if path == "/v1/openapi.json" {
			continue
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("documented route not protected or mounted: %s %d", path, w.Code)
		}
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("write accepted on read route: %s %s %d", method, path, w.Code)
			}
		}
	}
}
