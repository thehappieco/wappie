// Every security-relevant setting of the enclave reader, as constants of the
// image. This file is measured into PCR0, so changing any value changes the
// measurement the console and the KMS key policy pin: an operator cannot point
// a genuine image at another origin, console, archive or key. Nothing is read
// from the environment (the Dockerfile sets only NODE_ENV=production).
//
// The two KMS key ARNs are filled by deploy/enclave/build.sh, which replaces
// the `@@…@@` markers below in the build context before `docker build`; an
// image that still carries a marker refuses to boot (constants_invalid). They
// are ARNs by key id, never aliases: an UpdateAlias would swap the key.
export const READER_ID = 'enclave'
export const READER_VERSION = '0.3.0'
export const PUBLIC_HOST = 'mcp.wappie.thehappie.co'
export const PUBLIC_ORIGIN = `https://${PUBLIC_HOST}`
export const CONSOLE_URL = 'https://app.wappie.thehappie.co/console'
export const ARCHIVE = 'https://api.wappie.thehappie.co'
export const REDIRECT_HOSTS = Object.freeze(['claude.ai', 'chatgpt.com'])
export const CIMD = true
export const PENDING_TTL_MS = 1_200_000
export const REGION = 'eu-west-1'
export const KMS_READER_KEY_ARN = '@@KMS_READER_KEY_ARN@@'
export const KMS_BOOT_KEY_ARN = '@@KMS_BOOT_KEY_ARN@@'
export const ACME_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'
export const BOOT_NAME_SUFFIX = '.boot.mcp.wappie.thehappie.co'

// The listeners' exact Host headers (docs/mcp-enclave.md §5.1).
export const PUBLIC_LISTENER_HOST = PUBLIC_HOST
export const INTERNAL_LISTENER_HOST = `${PUBLIC_HOST}:8443`

// Loopback ports inside the enclave; entrypoint.sh bridges each to vsock.
export const PORTS = Object.freeze({ public: 5443, internal: 5444, challenge: 5445, credentials: 7000, boot: 7001, logSink: 7002 })
// Per-boot TLS material lives here (tmpfs): it survives a Node restart, never an enclave boot.
export const RUN_DIR = '/run/wappie'
export const NSM_ATTEST = '/usr/local/bin/nsm-attest'

const keyArn = /^arn:aws:kms:eu-west-1:\d{12}:key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** The constants as one object, or an Error('constants_invalid') when the build left a marker. */
export function imageConstants() {
  if (!keyArn.test(KMS_READER_KEY_ARN) || !keyArn.test(KMS_BOOT_KEY_ARN) || KMS_READER_KEY_ARN === KMS_BOOT_KEY_ARN) throw new Error('constants_invalid')
  return Object.freeze({
    READER_ID, READER_VERSION, PUBLIC_HOST, PUBLIC_ORIGIN, CONSOLE_URL, ARCHIVE, REDIRECT_HOSTS, CIMD, PENDING_TTL_MS, REGION,
    KMS_READER_KEY_ARN, KMS_BOOT_KEY_ARN, ACME_DIRECTORY, BOOT_NAME_SUFFIX, PUBLIC_LISTENER_HOST, INTERNAL_LISTENER_HOST, PORTS, RUN_DIR, NSM_ATTEST,
  })
}
