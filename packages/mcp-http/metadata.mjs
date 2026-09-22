// RFC 9728 protected-resource metadata and the RFC 8414 document of the
// in-process authorization server, served on all four well-known paths with
// identical bodies. The SDK helper answers two of them; the other two are the
// same request rewritten to the path it knows.
import { buildOAuthProtectedResourceMetadata, getOAuthProtectedResourceMetadataUrl, oauthMetadataResponse } from '@whatserver2/mcp/sdk'

export const SCOPE = 'wappie:read'
const prmPath = '/.well-known/oauth-protected-resource', asPath = '/.well-known/oauth-authorization-server'

export function createMetadata({ publicOrigin, cimd }) {
  const resource = `${publicOrigin}/mcp`
  const oauthMetadata = {
    issuer: publicOrigin,
    authorization_endpoint: `${publicOrigin}/mcp/authorize`, token_endpoint: `${publicOrigin}/mcp/token`,
    registration_endpoint: `${publicOrigin}/mcp/register`, revocation_endpoint: `${publicOrigin}/mcp/revoke`,
    response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'], scopes_supported: [SCOPE],
    authorization_response_iss_parameter_supported: true,
    ...(cimd ? { client_id_metadata_document_supported: true } : {}),
  }
  const options = { oauthMetadata, resourceServerUrl: new URL(resource), scopesSupported: [SCOPE], resourceName: 'Wappie' }
  const prm = buildOAuthProtectedResourceMetadata(options)
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
      return oauthMetadataResponse(target === path ? request : new Request(new URL(target, url), request), options)
    },
  }
}
