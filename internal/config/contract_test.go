package config

import (
	"os"
	"strings"
	"testing"
)

// The documentation placeholders AWS itself uses: no real account or key.
const (
	testKeyARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testRegion = "eu-west-1"
	// The current envelope's path, as the installer makes it.
	sealedCurrent = "/opt/wappie/sealed/contract-secret.thcseal"
)

func prodContract(t *testing.T) {
	t.Helper()
	minimalEnv(t)
	t.Setenv("WS_ENV", "prod")
	t.Setenv("WS_POSTGRES_DSN", "postgres://user:hunter2@db/whatserver2")
	t.Setenv("WS_CONTRACT_SOCKET", "/run/platform/contract.sock")
	t.Setenv("WS_CONTRACT_SECRET_FILE", sealedCurrent)
	t.Setenv("WS_CONTRACT_SECRET_OTHER_FILE", "/opt/wappie/sealed/contract-secret.other.thcseal")
	t.Setenv("WS_CONTRACT_KMS_KEY_ARN", testKeyARN)
	t.Setenv("WS_CONTRACT_KMS_REGION", testRegion)
}

func TestContractIsOffByDefault(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Contract.Configured() || cfg.Contract.Transport() != "none" || cfg.Contract.Sealed() {
		t.Fatalf("defaults: %+v", cfg.Contract)
	}
	if cfg.Contract.LoadedFile != DefaultContractLoaded {
		t.Fatalf("loaded file: %q", cfg.Contract.LoadedFile)
	}
}

func TestContractInProduction(t *testing.T) {
	prodContract(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Contract
	if !c.Configured() || c.Transport() != "socket" || !c.Sealed() || c.KMSRegion != testRegion {
		t.Fatalf("%+v", c)
	}
	// LoadContract reads the same, without the rest of the configuration.
	for _, k := range []string{"WS_POSTGRES_DSN", "WS_S3_BUCKET", "WS_S3_ACCESS_KEY", "WS_S3_SECRET_KEY"} {
		t.Setenv(k, "")
	}
	only, env, err := LoadContract()
	if err != nil || env != EnvProd || only != c {
		t.Fatalf("LoadContract: %+v %s %v", only, env, err)
	}
}

func TestContractRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[string]string
		want string
	}{
		{"the secret as a setting", map[string]string{"WS_CONTRACT_SECRET": "x"}, "WS_CONTRACT_SECRET is refused"},
		{"an empty secret setting", map[string]string{"WS_CONTRACT_SECRET": ""}, "WS_CONTRACT_SECRET is refused"},
		{"no socket", map[string]string{"WS_CONTRACT_SOCKET": ""}, "half configured"},
		{"the development address", map[string]string{"WS_CONTRACT_ADDR": "127.0.0.1:8291"}, "exclusive"},
		{"the development address alone", map[string]string{"WS_CONTRACT_SOCKET": "", "WS_CONTRACT_ADDR": "127.0.0.1:8291"}, "refused in prod"},
		{"a relative socket", map[string]string{"WS_CONTRACT_SOCKET": "contract.sock"}, "absolute path"},
		{"no secret file", map[string]string{"WS_CONTRACT_SECRET_FILE": ""}, "WS_CONTRACT_SECRET_FILE is required"},
		{"no other file", map[string]string{"WS_CONTRACT_SECRET_OTHER_FILE": ""}, "WS_CONTRACT_SECRET_OTHER_FILE is required in prod"},
		{"the same file twice", map[string]string{"WS_CONTRACT_SECRET_OTHER_FILE": sealedCurrent}, "another file"},
		{"no key", map[string]string{"WS_CONTRACT_KMS_KEY_ARN": "", "WS_CONTRACT_KMS_REGION": ""}, "required in prod"},
		{"a key without its region", map[string]string{"WS_CONTRACT_KMS_REGION": ""}, "go together"},
		{"an alias", map[string]string{"WS_CONTRACT_KMS_KEY_ARN": "arn:aws:kms:eu-west-1:111122223333:alias/wappie-contract-prod"}, "never an alias"},
		{"a key in another region", map[string]string{"WS_CONTRACT_KMS_REGION": "us-east-1"}, "never an alias"},
		{"a bare key id", map[string]string{"WS_CONTRACT_KMS_KEY_ARN": testKeyARN[strings.LastIndex(testKeyARN, "/")+1:]}, "never an alias"},
		{"a relative file", map[string]string{"WS_CONTRACT_SECRET_FILE": "sealed/contract-secret.thcseal"}, "absolute path in prod"},
		{"a relative published load", map[string]string{"WS_CONTRACT_LOADED_FILE": "contract-secrets.loaded"}, "absolute path in prod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prodContract(t)
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			// No message echoes a value it refuses.
			if err != nil && (strings.Contains(err.Error(), "111122223333") || strings.Contains(err.Error(), "=x")) {
				t.Fatalf("the error echoes a value: %v", err)
			}
			if _, _, err := LoadContract(); err == nil {
				t.Fatal("LoadContract accepted what Load refuses")
			}
		})
	}
}

func TestContractInDevelopment(t *testing.T) {
	minimalEnv(t)
	t.Setenv("WS_CONTRACT_ADDR", "127.0.0.1:8291")
	t.Setenv("WS_CONTRACT_SECRET_FILE", "contract-secret.txt")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c := cfg.Contract; c.Transport() != "tcp" || c.Sealed() || c.SecretOtherFile != "" {
		t.Fatalf("%+v", c)
	}
	for _, addr := range []string{"[::1]:8291", "127.0.0.2:8291"} {
		t.Setenv("WS_CONTRACT_ADDR", addr)
		if _, err := Load(); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.1:8291", "localhost:8291", "0.0.0.0:8291", "127.0.0.1", "127.0.0.1:"} {
		t.Setenv("WS_CONTRACT_ADDR", addr)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "loopback IP") {
			t.Errorf("%s: %v", addr, err)
		}
	}
	// Envelopes in development too, when a key is set.
	t.Setenv("WS_CONTRACT_ADDR", "127.0.0.1:8291")
	t.Setenv("WS_CONTRACT_KMS_KEY_ARN", testKeyARN)
	t.Setenv("WS_CONTRACT_KMS_REGION", testRegion)
	if cfg, err = Load(); err != nil || !cfg.Contract.Sealed() {
		t.Fatalf("%+v %v", cfg.Contract, err)
	}
	t.Setenv("WS_ENV", "staging")
	if _, _, err := LoadContract(); err == nil {
		t.Fatal("LoadContract took an unknown WS_ENV")
	}
}

func TestParseDotEnvTouchesNoEnvironment(t *testing.T) {
	const body = `
# runtime.env, as the installer reads it
WS_POSTGRES_DSN=postgres://wappie:hunter2@db/wappie
export WS_CONTRACT_KMS_KEY_ARN="arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
WS_CONTRACT_KMS_REGION = eu-west-1
WS_CONTRACT_KMS_REGION=us-east-1
`
	for _, k := range []string{"WS_POSTGRES_DSN", "WS_CONTRACT_KMS_KEY_ARN", "WS_CONTRACT_KMS_REGION"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ParseDotEnv(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if got["WS_CONTRACT_KMS_KEY_ARN"] != testKeyARN || got["WS_CONTRACT_KMS_REGION"] != testRegion || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	for _, k := range []string{"WS_POSTGRES_DSN", "WS_CONTRACT_KMS_KEY_ARN", "WS_CONTRACT_KMS_REGION"} {
		if _, set := os.LookupEnv(k); set {
			t.Errorf("ParseDotEnv set %s", k)
		}
	}
	// A malformed line is named, its text never echoed: it may be a secret.
	_, err = ParseDotEnv(strings.NewReader("WS_OK=1\nhunter2-pasted-alone\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("malformed: %v", err)
	}
	if _, err := ParseDotEnv(strings.NewReader("=value\n")); err == nil || !strings.Contains(err.Error(), "empty key") {
		t.Fatalf("empty key: %v", err)
	}
}
