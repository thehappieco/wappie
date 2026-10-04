// RFC 8785, the JSON Canonicalization Scheme.
//
// One serialization of a JSON value that two parties compute independently and
// hash: the console over a consent's scope before it seals the bundle, the
// attested reader over the scope it opened (docs/mcp-enclave.md §17.2, the
// device check). A difference of one byte fails the check, so both sides call
// this one function and nothing else.
//
// The implementation is the shared kit's (@thehappieco/kit/jcs), which started
// as this file and has a Go twin there.

export { CanonicalJSONError, canonicalJSON } from '@thehappieco/kit/jcs'
