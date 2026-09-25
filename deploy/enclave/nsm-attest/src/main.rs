// nsm-attest: asks the Nitro Secure Module for an attestation document and
// writes the raw COSE_Sign1 bytes to stdout. The reader runs it before every
// KMS call and for every consent attestation, so the arguments and exit codes
// are a fixed contract (the public key is opaque bytes: an RSA SPKI or a raw
// X25519 key):
//   nsm-attest <public_key_hex|-> <nonce_hex|-> <user_data_hex|->
//   0 document on stdout, 1 NSM error, 2 no /dev/nsm, 3 bad arguments
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::process::exit;

const USAGE: &str = "usage: nsm-attest <public_key_hex|-> <nonce_hex|-> <user_data_hex|->";

// One line on stderr, never document bytes or argument contents. A failed
// stderr write is ignored so it cannot turn into an abort with another code.
fn fail(code: i32, reason: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "nsm-attest: {reason}");
    exit(code)
}

// "-" means absent. The limits are attestation_process.md's (512, not the
// CDDL's 1024), so the NSM never signs a document a verifier would reject.
fn field(name: &str, arg: &OsStr, min: usize, max: usize) -> Option<ByteBuf> {
    let text = arg.to_str().unwrap_or_else(|| fail(3, &format!("{name}: not text")));
    if text == "-" {
        return None;
    }
    let bytes = hex::decode(text).unwrap_or_else(|_| fail(3, &format!("{name}: not hex")));
    if !(min..=max).contains(&bytes.len()) {
        fail(3, &format!("{name}: {} bytes, want {min}..={max}", bytes.len()));
    }
    Some(ByteBuf::from(bytes))
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        fail(3, USAGE);
    }
    // Validate before touching the device, so bad arguments exit 3 anywhere.
    let public_key = field("public_key", &args[0], 1, 1024);
    let nonce = field("nonce", &args[1], 0, 512);
    let user_data = field("user_data", &args[2], 0, 512);

    let fd = nsm_init();
    if fd < 0 {
        fail(2, "cannot open /dev/nsm");
    }
    let response = nsm_process_request(fd, Request::Attestation { user_data, nonce, public_key });
    nsm_exit(fd);

    // Response is #[non_exhaustive], hence the catch-all arm.
    let document = match response {
        Response::Attestation { document } => document,
        Response::Error(code) => fail(1, &format!("nsm error: {code:?}")),
        _ => fail(1, "nsm returned an unexpected response"),
    };
    let mut out = std::io::stdout().lock();
    if out.write_all(&document).and_then(|()| out.flush()).is_err() {
        fail(1, "cannot write the document to stdout");
    }
}
