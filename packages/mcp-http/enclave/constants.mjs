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
export const READER_VERSION = '0.6.0'
// What this release can do, for the console (build.sh writes it into
// measurements.json as `capabilities`, docs/mcp-enclave.md §16.2 rule 8,
// §17.2 rule 9, §18.14 and §19.3): consent version 2, attachments for a
// consent that includes them, consent version 3 (the card with sending and
// its device checks), drafts, with own-chat sends riding on them, AI
// integrations on request (`ai_v1`, §18), and, from 0.6.0 (§19), any MCP
// client that identifies itself by a document (`any_client_v1`), descriptors
// attested whole (`descriptor_attest_v2`), consent version 4 with its ticks
// and link bundle v2 (`consent_v4`), the tiers' limits (`client_limits_v1`),
// the attested live list (`live_list_v1`) and the console connection token
// (`console_token_v1`). Direct send (`send_direct_v1`) comes after 0.6.0.
// Without `ai_v1` content.mjs builds no AI service at all.
export const READER_CAPABILITIES = Object.freeze(['consent_v2', 'media', 'consent_v3', 'send_draft_v1', 'ai_v1',
  'any_client_v1', 'descriptor_attest_v2', 'consent_v4', 'client_limits_v1', 'live_list_v1', 'console_token_v1'])
export const PUBLIC_HOST = 'mcp.wappie.thehappie.co'
export const PUBLIC_ORIGIN = `https://${PUBLIC_HOST}`
export const CONSOLE_URL = 'https://app.wappie.thehappie.co/console'
export const ARCHIVE = 'https://api.wappie.thehappie.co'

/** Freezes an object and everything inside it. */
export function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

// Which clients are admitted (docs/mcp-enclave.md §19.3). cimd 'any' admits a
// CIMD client on any host that passes §19.5; 'allowlist' is 0.5.0's rule,
// kept for the tests and the hosted path. dcr 'pinned' admits only the
// pinned DCR redirects (§19.8).
export const CLIENT_POLICY = Object.freeze({ cimd: 'any', dcr: 'pinned' })
// TODO(baseline B on reader 0.5.0, docs/mcp-enclave.md §19.4): PENDING.
// These are D3's candidates, not yet the tested list. An entry stays only if
// its client passed the whole script on 0.5.0; the lead replaces each
// client_id and redirect with the exact values the baseline recorded and
// removes any client that failed. A change is a release. build.sh copies this
// list and CLIENT_LIMITS into measurements.json.
export const TESTED_CLIENTS = deepFreeze([
  { id: 'claude', kind: 'cimd', client_id: 'https://claude.ai/oauth/mcp-oauth-client-metadata', name: 'Claude', local: false, profile: 'claude.ai',
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback'] },
  { id: 'chatgpt', kind: 'cimd', client_id: 'https://chatgpt.com/oauth/client.json', name: 'ChatGPT', local: false, profile: 'chatgpt.com',
    redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'] },
  { id: 'chatgpt_cb', kind: 'cimd_pattern', client_id: 'https://chatgpt.com/oauth/{cb}/client.json', name: 'ChatGPT', local: false, profile: 'chatgpt.com',
    redirect_uris: ['https://chatgpt.com/connector/oauth/{cb}'], cb: '^[A-Za-z0-9_-]{1,64}$' },
  { id: 'codex', kind: 'cimd', client_id: 'https://chatgpt.com/oauth/codex/client.json', name: 'Codex', local: true, profile: 'chatgpt.com',
    loopback: [['127.0.0.1', '/callback'], ['localhost', '/callback']] },
  { id: 'claude_code', kind: 'cimd', client_id: 'https://claude.ai/oauth/claude-code-client-metadata', name: 'Claude Code', local: true, profile: 'claude.ai',
    loopback: [['localhost', '/callback'], ['127.0.0.1', '/callback']] },
  { id: 'claude_dcr', kind: 'dcr', name: 'Claude', local: false, profile: 'claude.ai',
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback'] },
  { id: 'chatgpt_dcr', kind: 'dcr', name: 'ChatGPT', local: false, profile: 'chatgpt.com',
    redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect', 'https://chatgpt.com/connector/oauth/{cb}'], cb: '^[A-Za-z0-9_-]{1,64}$' },
])
// The limits of each tier (§19.19): how long a refresh token lives unused and
// the furthest expiry a consent may ask, per kind; the card's duration
// choices; the calls a minute; the history a connection reaches (null: all);
// what it may read in a rolling day and in its first hour (null: no limit).
export const CLIENT_LIMITS = deepFreeze({
  web_tested: {
    idle_days: { metadata: 30, content: 7 }, ceiling_hours: { metadata: 366 * 24, content: 90 * 24 + 1 },
    durations_days: { metadata: { choices: [30, 90, 365], default: 90 }, content: { choices: [1, 30, 90], default: 30 } },
    calls_per_minute: 60, history_days: null, daily: null, first_hour: null },
  local_tested: {
    idle_days: { metadata: 7, content: 7 }, ceiling_hours: { metadata: 90 * 24 + 1, content: 30 * 24 + 1 },
    durations_days: { metadata: { choices: [7, 30, 90], default: 30 }, content: { choices: [1, 7, 30], default: 7 } },
    calls_per_minute: 60, history_days: null, daily: null, first_hour: null },
  unknown: {
    idle_days: { metadata: 7, content: 3 }, ceiling_hours: { metadata: 90 * 24 + 1, content: 30 * 24 + 1 },
    durations_days: { metadata: { choices: [7, 30, 90], default: 30 }, content: { choices: [1, 7, 30], default: 7 } },
    calls_per_minute: 20, history_days: { choices: [7, 30, 90], default: 30 },
    daily: { messages: 2000, attachments: 50 }, first_hour: { messages: 300, attachments: 10 } },
  token: {
    idle_days: null, ceiling_hours: { metadata: 90 * 24 + 1, content: 30 * 24 + 1 },
    durations_days: { metadata: { choices: [7, 30, 90], default: 30 }, content: { choices: [1, 7, 30], default: 1 } },
    calls_per_minute: 20, history_days: { choices: [7, 30, 90], default: 30 },
    daily: { messages: 2000, attachments: 50 }, first_hour: { messages: 300, attachments: 10 } },
})
// Live unknown and token connections per workspace, inside Go's cap of 10 (§19.10).
export const UNKNOWN_LIVE_MAX = 3
// Hosts that serve many tenants by path, let an uploader set the content
// type, or log every request: refused as CIMD hosts, as the host or any
// subdomain (§19.5 step 4.8).
export const SHARED_HOSTS = Object.freeze(['amazonaws.com', 'storage.googleapis.com', 'firebasestorage.googleapis.com',
  'googleusercontent.com', 'githubusercontent.com', 'webhook.site', 'cdn.jsdelivr.net', 'unpkg.com', 'raw.githack.com',
  'pipedream.net', 'requestbin.com', 'beeceptor.com'])
// Registrable domains that are Wappie's own: every host under them is refused.
export const OWN_DOMAINS = Object.freeze(['thehappie.co'])
// The document egress proxy on the parent (§19.9): entrypoint.sh bridges the
// address and port to vsock 8007, where only CONNECT <host>:443 is accepted.
export const CIMD_EGRESS = Object.freeze({ address: '127.0.0.8', port: 3128, vsock: 8007 })
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
    READER_ID, READER_VERSION, READER_CAPABILITIES, PUBLIC_HOST, PUBLIC_ORIGIN, CONSOLE_URL, ARCHIVE,
    CLIENT_POLICY, TESTED_CLIENTS, CLIENT_LIMITS, UNKNOWN_LIVE_MAX, SHARED_HOSTS, OWN_DOMAINS, CIMD_EGRESS, PENDING_TTL_MS, REGION,
    KMS_READER_KEY_ARN, KMS_BOOT_KEY_ARN, ACME_DIRECTORY, BOOT_NAME_SUFFIX, PUBLIC_LISTENER_HOST, INTERNAL_LISTENER_HOST, PORTS, RUN_DIR, NSM_ATTEST,
  })
}
