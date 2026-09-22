// The one MCP SDK instance every Wappie package shares. Hosted readers import
// the server SDK from here so class identity checks inside the SDK hold across
// packages; nothing else in this file.
export * from '@modelcontextprotocol/server'
export { serveStdio, StdioServerTransport } from '@modelcontextprotocol/server/stdio'
