// RFC 9728 protected-resource metadata and the RFC 8414 document of the
// in-process authorization server, served on all four well-known paths with
// identical bodies. The SDK helper answers two of them; the other two are the
// same request rewritten to the path it knows.
//
// From reader 0.6.0 (docs/mcp-enclave.md §19.29) `links` names the pages a
// person or a directory reviewer reads about this server: its documentation
// (`resource_documentation`, `service_documentation`), privacy policy
// (`resource_policy_uri`, `op_policy_uri`) and terms (`resource_tos_uri`,
// `op_tos_uri`). The attested reader passes its image constants; a reader
// given none (the hosted one, a self-hosted container) names none, since an
// operator's own policy is not Wappie's.
import { buildOAuthProtectedResourceMetadata, getOAuthProtectedResourceMetadataUrl, oauthMetadataResponse } from '@whatserver2/mcp/sdk'

export const SCOPE = 'wappie:read'
const prmPath = '/.well-known/oauth-protected-resource', asPath = '/.well-known/oauth-authorization-server'
/** A link a document may carry: a plain https URL, else nothing. */
const httpsLink = value => (typeof value === 'string' && /^https:\/\/[^\s<>"'`]+$/.test(value) && URL.canParse(value) ? new URL(value).href : undefined)

export function createMetadata({ publicOrigin, cimd, links = {} }) {
  const resource = `${publicOrigin}/mcp`
  const documentation = httpsLink(links.documentation), privacy = httpsLink(links.privacy), terms = httpsLink(links.terms)
  const oauthMetadata = {
    issuer: publicOrigin,
    authorization_endpoint: `${publicOrigin}/mcp/authorize`, token_endpoint: `${publicOrigin}/mcp/token`,
    registration_endpoint: `${publicOrigin}/mcp/register`, revocation_endpoint: `${publicOrigin}/mcp/revoke`,
    response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'], scopes_supported: [SCOPE],
    authorization_response_iss_parameter_supported: true,
    ...(cimd ? { client_id_metadata_document_supported: true } : {}),
    ...(documentation ? { service_documentation: documentation } : {}),
    ...(privacy ? { op_policy_uri: privacy } : {}),
    ...(terms ? { op_tos_uri: terms } : {}),
  }
  const options = { oauthMetadata, resourceServerUrl: new URL(resource), scopesSupported: [SCOPE], resourceName: 'Wappie',
    ...(documentation ? { serviceDocumentationUrl: new URL(documentation) } : {}) }
  // RFC 9728 §2's policy and terms, which the SDK's builder does not know.
  const prm = { ...buildOAuthProtectedResourceMetadata(options), ...(privacy ? { resource_policy_uri: privacy } : {}), ...(terms ? { resource_tos_uri: terms } : {}) }
  const extended = Boolean(privacy || terms)
  const served = { [prmPath]: `${prmPath}/mcp`, [`${prmPath}/mcp`]: `${prmPath}/mcp`, [asPath]: asPath, [`${asPath}/mcp`]: asPath }
  return {
    resource, oauthMetadata, prm,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(resource)),
    paths: Object.keys(served),
    /** The metadata response for a well-known path, or undefined for any other path. */
    respond(request) {
      const url = new URL(request.url)
      const path = url.pathname.length > 1 && url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname
      const target = served[path]
      if (!target) return undefined
      // The protected-resource document with the fields the SDK leaves out, as the SDK serves it (CORS open, HEAD without a body).
      if (target !== asPath && extended && (request.method === 'GET' || request.method === 'HEAD')) {
        return new Response(request.method === 'HEAD' ? null : JSON.stringify(prm), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } })
      }
      return oauthMetadataResponse(target === path ? request : new Request(new URL(target, url), request), options)
    },
  }
}
