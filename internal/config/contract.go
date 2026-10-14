package config

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Contract is how this server reaches The Happie Co's platform over the
// product contract's membership part (decision 0040; docs/contract.md): the
// transport and the secret's two files. It says nothing about what the
// server does with it: the mode (off, observe) lives in the database, so
// that a container or a restored runtime.env without these settings never
// reopens what the contract closed.
//
// Unset is off, the self-hosted default: nothing calls the platform. Set,
// it is all or nothing, as object storage is.
type Contract struct {
	// Socket is the platform's contract socket, /run/platform/contract.sock
	// (WS_CONTRACT_SOCKET): set means the transport is configured. The
	// unit joins platform-contract to reach it.
	Socket string
	// Addr, development only, is the platform's loopback TCP transport,
	// 127.0.0.1:8291 (WS_CONTRACT_ADDR). Refused in prod, beside the
	// socket, and for any address that is not a loopback IP.
	Addr string
	// SecretFile holds the secret this server signs with, and
	// SecretOtherFile, during a rotation, the other one it also accepts on
	// answers (WS_CONTRACT_SECRET_FILE, WS_CONTRACT_SECRET_OTHER_FILE). Each
	// is a THCSEAL envelope under Wappie's KMS key; in development without
	// a key, the 43 characters in plain text. The other file may be absent
	// on disk: no rotation is under way.
	SecretFile      string
	SecretOtherFile string
	// KMSKeyARN is Wappie's own key, a full key ARN, never an alias, and
	// KMSRegion its region (WS_CONTRACT_KMS_KEY_ARN, WS_CONTRACT_KMS_REGION).
	// Required in prod beside the socket.
	KMSKeyARN string
	KMSRegion string
	// LoadedFile is where the server publishes what it loaded, after every
	// load and reload (WS_CONTRACT_LOADED_FILE, by default in the API unit's
	// state directory): fingerprints of the envelopes, never the secret.
	// The installer waits for it before it calls a step done.
	LoadedFile string
}

// DefaultContractLoaded is the published load's path unless
// WS_CONTRACT_LOADED_FILE says otherwise: the API unit's state directory.
const DefaultContractLoaded = "/var/lib/wappie/contract-secrets.loaded"

// Configured reports whether a transport to the platform is set.
func (c Contract) Configured() bool { return c.Socket != "" || c.Addr != "" }

// Sealed reports whether the secret's files are envelopes under a KMS key;
// otherwise, in development, they are plain text.
func (c Contract) Sealed() bool { return c.KMSKeyARN != "" }

// Transport names the transport for the start line: socket, tcp or none.
func (c Contract) Transport() string {
	switch {
	case c.Socket != "":
		return "socket"
	case c.Addr != "":
		return "tcp"
	}
	return "none"
}

// LoadContract reads only the contract's settings and WS_ENV from the
// environment, for the commands that need nothing else (contract check
// runs as the service user with runtime.env as its environment, and never
// reads a .env): the same rules as Load's.
func LoadContract() (Contract, Env, error) {
	env := Env(str("WS_ENV", string(EnvDev)))
	if env != EnvDev && env != EnvProd {
		return Contract{}, env, errors.New("config: WS_ENV: want dev or prod")
	}
	c := loadContract()
	if err := c.Validate(env.IsProd()); err != nil {
		return Contract{}, env, err
	}
	return c, env, nil
}

func loadContract() Contract {
	return Contract{
		Socket:          strings.TrimSpace(os.Getenv("WS_CONTRACT_SOCKET")),
		Addr:            strings.TrimSpace(os.Getenv("WS_CONTRACT_ADDR")),
		SecretFile:      strings.TrimSpace(os.Getenv("WS_CONTRACT_SECRET_FILE")),
		SecretOtherFile: strings.TrimSpace(os.Getenv("WS_CONTRACT_SECRET_OTHER_FILE")),
		KMSKeyARN:       strings.TrimSpace(os.Getenv("WS_CONTRACT_KMS_KEY_ARN")),
		KMSRegion:       strings.TrimSpace(os.Getenv("WS_CONTRACT_KMS_REGION")),
		LoadedFile:      strings.TrimSpace(str("WS_CONTRACT_LOADED_FILE", DefaultContractLoaded)),
	}
}

// Validate refuses a half or unsafe configuration. The messages name
// settings, never their values.
func (c Contract) Validate(prod bool) error {
	var errs []error
	bad := func(msg string) { errs = append(errs, errors.New(msg)) }
	// The secret is never a setting: a value in the environment is in
	// every child process and every crash report. Nothing reads it, so
	// refusing it everywhere keeps it from being set by mistake.
	if _, set := os.LookupEnv("WS_CONTRACT_SECRET"); set {
		bad("WS_CONTRACT_SECRET is refused: the contract secret lives in WS_CONTRACT_SECRET_FILE, a THCSEAL envelope in prod")
	}
	if !c.Configured() {
		if c.SecretFile != "" || c.SecretOtherFile != "" || c.KMSKeyARN != "" || c.KMSRegion != "" {
			bad("the contract is half configured: WS_CONTRACT_SECRET_FILE, WS_CONTRACT_SECRET_OTHER_FILE and " +
				"WS_CONTRACT_KMS_* need WS_CONTRACT_SOCKET (or WS_CONTRACT_ADDR in development)")
		}
		return errors.Join(errs...)
	}
	if c.Socket != "" && c.Addr != "" {
		bad("WS_CONTRACT_SOCKET and WS_CONTRACT_ADDR are exclusive: set the socket in prod, the address in development")
	}
	if c.Socket != "" && !filepath.IsAbs(c.Socket) {
		bad("WS_CONTRACT_SOCKET must be an absolute path")
	}
	if c.Addr != "" {
		if prod {
			bad("WS_CONTRACT_ADDR is the platform's development transport and is refused in prod: set WS_CONTRACT_SOCKET")
		} else if !loopbackAddr(c.Addr) {
			bad("WS_CONTRACT_ADDR must be a loopback IP and a port, such as 127.0.0.1:8291")
		}
	}
	if c.SecretFile == "" {
		bad("WS_CONTRACT_SECRET_FILE is required with the contract's transport")
	}
	if c.SecretOtherFile != "" && c.SecretOtherFile == c.SecretFile {
		bad("WS_CONTRACT_SECRET_OTHER_FILE must be another file than WS_CONTRACT_SECRET_FILE")
	}
	if (c.KMSKeyARN == "") != (c.KMSRegion == "") {
		bad("WS_CONTRACT_KMS_KEY_ARN and WS_CONTRACT_KMS_REGION go together")
	} else if c.KMSKeyARN != "" && !kmsKeyARN(c.KMSKeyARN, c.KMSRegion) {
		bad("WS_CONTRACT_KMS_KEY_ARN must be a full KMS key ARN (never an alias) in WS_CONTRACT_KMS_REGION")
	}
	if prod {
		// Production keeps the secret tier 2 (README 7.3): both envelopes,
		// Wappie's key, absolute paths, and never a plain-text file.
		if c.SecretOtherFile == "" {
			bad("WS_CONTRACT_SECRET_OTHER_FILE is required in prod, where rotations happen")
		}
		if c.KMSKeyARN == "" {
			bad("WS_CONTRACT_KMS_KEY_ARN and WS_CONTRACT_KMS_REGION are required in prod: the secret's files are THCSEAL envelopes there")
		}
		for _, f := range []struct{ name, path string }{
			{"WS_CONTRACT_SECRET_FILE", c.SecretFile},
			{"WS_CONTRACT_SECRET_OTHER_FILE", c.SecretOtherFile},
			{"WS_CONTRACT_LOADED_FILE", c.LoadedFile},
		} {
			if f.path != "" && !filepath.IsAbs(f.path) {
				bad(f.name + " must be an absolute path in prod")
			}
		}
	}
	return errors.Join(errs...)
}

// loopbackAddr reports a loopback IP literal and a port: the platform's
// development transport listens there and nowhere else.
func loopbackAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// kmsKeyARN reports a full KMS key ARN in region: arn:<partition>:kms:
// <region>:<account>:key/<id>. The kit's awskms checks it again, and
// DescribeKey checks that it is the key this server must use.
func kmsKeyARN(arn, region string) bool {
	parts := strings.SplitN(arn, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[1] != "" && parts[2] == "kms" &&
		parts[3] == region && parts[4] != "" && strings.HasPrefix(parts[5], "key/") && len(parts[5]) > len("key/")
}
