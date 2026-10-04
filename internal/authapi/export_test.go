package authapi

// PasskeySalt is the PRF evaluation input a provider hands to WebAuthn, for
// the test that holds it to the kit's vectors.
func PasskeySalt(p *PasskeyProvider) []byte { return p.salt }
